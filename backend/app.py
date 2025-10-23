import os
import sqlite3
import asyncio
import secrets
import io
import base64
from datetime import datetime, timedelta
from typing import Dict

from fastapi import FastAPI, Request, HTTPException, Body, Query
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

import qrcode
import csv
import time
import jwt
from typing import Optional

# =========================
# 환경/전역
# =========================
EXPORT_ROOT = os.path.join(os.path.dirname(__file__), "exports")
os.makedirs(EXPORT_ROOT, exist_ok=True)

QR_SECRET = os.getenv("QR_SECRET", "change-me")  # 운영에서는 환경변수로 지정
JWT_ALG = "HS256"
LATEST_QR_NONCE: dict[int, str] = {}            # 세션별 최신 QR nonce 저장
FORM_TOKENS: dict[str, dict] = {}

FORM_TOKEN_TTL_SECONDS = 60  # 페이지 진입 후 1분 동안 제출 허용 (원하면 조정)

app = FastAPI()
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(os.path.dirname(__file__), "../frontend/static")),
    name="static",
)
DB_PATH = os.path.join(os.path.dirname(__file__), "attendai.db")
QR_PERIOD_SECONDS = 15  # 표시용 기본 주기(대시보드 타이머와 맞추기)

# =========================
# DB 유틸
# =========================
def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS students(id TEXT PRIMARY KEY, name TEXT, email TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS classes(id TEXT PRIMARY KEY, name TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY AUTOINCREMENT, class_id TEXT, start_time TEXT, end_time TEXT)")
    # 아래 테이블은 과거 방식 유산. 남겨두지만 사용하진 않음.
    cur.execute("CREATE TABLE IF NOT EXISTS qr_tokens(id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, token TEXT, generated_at TEXT, valid_until TEXT)")
    cur.execute("""CREATE TABLE IF NOT EXISTS attendance_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        student_id TEXT,
        checked_at TEXT,
        ip TEXT,
        user_agent TEXT,
        token TEXT,
        qr_generated_at TEXT,
        anomaly_flags TEXT,
        device_name TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS email_excuses(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT,
        session_date TEXT,
        excuse_type TEXT,
        evidence_ok INTEGER,
        notes TEXT,
        msg_id TEXT,
        ai_label TEXT,
        ai_confidence REAL,
        ai_reason TEXT
    )""")
    conn.commit()
    cur.execute("INSERT OR IGNORE INTO classes(id,name) VALUES(?,?)", ("CLS101","Default Class"))
    conn.commit()
    # 오늘 세션 없으면 2시간짜리 하나 생성
    today = datetime.now().strftime("%Y-%m-%d")
    cur.execute("SELECT id FROM sessions WHERE date(start_time)=?", (today,))
    row = cur.fetchone()
    if not row:
        start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        end = (datetime.now()+timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("INSERT INTO sessions(class_id,start_time,end_time) VALUES(?,?,?)", ("CLS101", start, end))
        conn.commit()
    conn.close()

def migrate_db():
    conn = db()
    cur = conn.cursor()
    # idempotent migration들
    try:
        cur.execute("ALTER TABLE email_excuses ADD COLUMN msg_id TEXT")
        cur.execute("ALTER TABLE email_excuses ADD COLUMN ai_label TEXT")
        cur.execute("ALTER TABLE email_excuses ADD COLUMN ai_confidence REAL")
        cur.execute("ALTER TABLE email_excuses ADD COLUMN ai_reason TEXT")
        conn.commit()
    except Exception:
        pass
    try:
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_email_excuses_msgid ON email_excuses(msg_id)")
        conn.commit()
    except Exception:
        pass
    try:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS excused_attendance(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id INTEGER,
          student_id TEXT,
          excuse_type TEXT,
          evidence_ok INTEGER,
          notes TEXT,
          source TEXT,
          created_at TEXT,
          UNIQUE(session_id, student_id)
        )
        """)
        conn.commit()
    except Exception:
        pass
    conn.close()

# =========================
# 공통 유틸
# =========================
def _sanitize_notes(s: str) -> str:
    return (s or "").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

def _csv_bytes(rows, header, *, encoding="cp949"):
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    w.writerow(header)
    for row in rows:
        w.writerow(row)
    text = buf.getvalue()
    if encoding.lower() == "utf-8":
        return ("\ufeff" + text).encode("utf-8")  # UTF-8 BOM
    return text.encode("cp949", errors="replace")

def current_session_id():
    conn = db()
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("SELECT id FROM sessions WHERE start_time<=? AND end_time>=? ORDER BY id DESC LIMIT 1", (now, now))
    row = cur.fetchone()
    conn.close()
    if row:
        return row["id"]
    return None

def client_ip(request: Request):
    xf = request.headers.get("x-forwarded-for")
    if xf:
        return xf.split(",")[0].strip()
    return request.client.host

# =========================
# QR(JWT) 발급/검증
# =========================
def _verify_qr_token(t: str):
    """
    JWT 유효성 + 최신 nonce 확인
    """
    try:
        data = jwt.decode(t, QR_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="QR expired")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid QR")

    sid = int(data.get("sid", 0))
    nonce = data.get("nonce")
    if not sid or not nonce:
        raise HTTPException(status_code=400, detail="Invalid QR payload")

    if LATEST_QR_NONCE.get(sid) != nonce:
        # 회전됨 (예전 QR)
        raise HTTPException(status_code=410, detail="QR rotated")

    return sid, nonce, data

def _new_qr_token(session_id: int, ttl: int = QR_PERIOD_SECONDS) -> tuple[str, int, str]:
    """
    새 JWT를 발급하고 최신 nonce를 갱신한다.
    반환: (token, exp_epoch, ga_iso)
    """
    nonce = secrets.token_urlsafe(8)
    now = int(time.time())
    exp = now + max(5, ttl)
    ga_iso = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    payload = {"sid": session_id, "nonce": nonce, "exp": exp, "ga": ga_iso}
    token = jwt.encode(payload, QR_SECRET, algorithm=JWT_ALG)
    LATEST_QR_NONCE[session_id] = nonce
    return token, exp, ga_iso

# =========================
# 라우트: QR 발급/종료/이미지
# =========================
@app.post("/api/qr/issue")
def issue_qr(session_id: int, ttl: int = QR_PERIOD_SECONDS):
    token, exp, _ = _new_qr_token(session_id, ttl)
    return {"token": token, "exp": exp}

@app.post("/api/qr/stop")
def stop_qr(session_id: int = Query(...)):
    LATEST_QR_NONCE.pop(session_id, None)
    return {"stopped": True}

@app.get("/api/qr/image")
async def api_qr_image(session_id: int = None, request: Request = None):
    sid = session_id or current_session_id()
    if not sid:
        raise HTTPException(status_code=404, detail="no active session")

    # 현재 최신 nonce가 없으면 하나 만든다
    nonce = LATEST_QR_NONCE.get(sid)
    if not nonce:
        nonce = secrets.token_urlsafe(8)
        LATEST_QR_NONCE[sid] = nonce

    vu = datetime.now() + timedelta(seconds=QR_PERIOD_SECONDS)
    t = jwt.encode({"sid": sid, "nonce": nonce, "exp": int(vu.timestamp())}, QR_SECRET, algorithm=JWT_ALG)

    base = str(request.base_url).rstrip("/")
    url = f"{base}/checkin?t={t}"   # ✅ JWT 기반 링크

    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# =========================
# 라우트: 체크인 페이지(토큰 필요)
# =========================
EXPIRED_HTML = """
<!doctype html><meta charset="utf-8">
<style>body{font-family:system-ui;padding:40px;text-align:center}</style>
<h2>QR 유효시간이 지났습니다</h2>
<p>새 QR 코드로 다시 접속해주세요.</p>
"""

@app.get("/api/qr/current")
def api_qr_current(session_id: Optional[int] = None):
    # 세션이 없으면 생성
    sid = session_id or current_session_id()
    if not sid:
        conn = db(); cur = conn.cursor()
        start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        end   = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("INSERT INTO sessions(class_id, start_time, end_time) VALUES(?,?,?)",
                    ("CLS101", start, end))
        conn.commit()
        sid = cur.lastrowid
        conn.close()

    # 새 nonce 발급(15초마다 대시보드가 다시 받아가므로 매 호출마다 갱신해도 OK)
    nonce = secrets.token_urlsafe(8)
    LATEST_QR_NONCE[sid] = nonce

    ga = datetime.now()
    vu = ga + timedelta(seconds=QR_PERIOD_SECONDS)
    payload = {"sid": sid, "nonce": nonce, "exp": int(vu.timestamp())}
    token = jwt.encode(payload, QR_SECRET, algorithm=JWT_ALG)

    return {
        "session_id": sid,
        "token": token,  # JWT
        "generated_at": ga.strftime("%Y-%m-%d %H:%M:%S"),
        "valid_until":  vu.strftime("%Y-%m-%d %H:%M:%S"),
    }
    
@app.get("/checkin", response_class=HTMLResponse)
def checkin_page(t: str = Query(...)):
    try:
        sid, nonce, data = _verify_qr_token(t)  # 최신 nonce & 만료 검증
    except HTTPException:
        return HTMLResponse(EXPIRED_HTML, status_code=410)

    # 폼 토큰 발급(2분 유효, 1회용)
    form_token = secrets.token_urlsafe(24)
    exp = int(time.time()) + FORM_TOKEN_TTL_SECONDS
    issued_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    FORM_TOKENS[form_token] = {"sid": sid, "issued_at": issued_at, "exp": exp}

    with open("frontend/checkin.html", "r", encoding="utf-8") as f:
        html = (
            f.read()
            .replace("%%TOKEN%%", form_token)   # ✅ 폼 토큰 주입
            .replace("%%SID%%", str(sid))       # ✅ 세션ID 주입
        )
    return HTMLResponse(html)

@app.get("/api/export/session/{session_id}/anomaly.csv")
async def api_export_anomaly_csv(session_id: int, min_score: int = 0):
    """
    현재 세션의 의심 행위 점수 계산 결과를 CSV로 다운로드.
    min_score: 이 값 이하(<=)만 포함시키고 싶으면 지정 (예: 70)
    """
    conn = db()
    cur = conn.cursor()

    # 세션 존재 확인 + 시간 범위
    cur.execute("SELECT start_time, end_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")
    s_start = datetime.strptime(srow["start_time"], "%Y-%m-%d %H:%M:%S")
    s_end = datetime.strptime(srow["end_time"], "%Y-%m-%d %H:%M:%S")

    # 로그 가져오기 (device_name 포함 버전으로)
    cur.execute("""
        SELECT student_id, checked_at, ip, qr_generated_at, device_name
        FROM attendance_logs
        WHERE session_id=?
        ORDER BY id ASC
    """, (session_id,))
    rows = cur.fetchall()
    conn.close()

    # ====== 아래는 기존 api_anomaly와 동일 로직 ======
    ip_to_students = {}
    device_to_students = {}
    student_counts = {}
    fast_flags = set()
    dup_flags = set()
    shared_ip_flags = set()
    shared_device_flags = set()
    out_of_window = set()
    burst_flags = set()
    seen = set()
    prev_by_student = {}

    for r in rows:
        k = (r["student_id"], r["ip"], r["checked_at"])
        student_counts[r["student_id"]] = student_counts.get(r["student_id"], 0) + 1

        ip_to_students.setdefault(r["ip"], set()).add(r["student_id"])

        dn = (r["device_name"] or "").strip()
        if dn:
            device_to_students.setdefault(dn, set()).add(r["student_id"])

        ga = datetime.strptime(r["qr_generated_at"], "%Y-%m-%d %H:%M:%S")
        ca = datetime.strptime(r["checked_at"], "%Y-%m-%d %H:%M:%S")

        if (ca - ga).total_seconds() < 2:
            fast_flags.add(r["student_id"])
        if k in seen:
            dup_flags.add(r["student_id"])
        seen.add(k)

        if ca < s_start or ca > s_end:
            out_of_window.add(r["student_id"])

        if r["student_id"] in prev_by_student:
            prev = prev_by_student[r["student_id"]]
            if (ca - prev).total_seconds() <= 5:
                burst_flags.add(r["student_id"])
        prev_by_student[r["student_id"]] = ca

    for ip, sset in ip_to_students.items():
        if len(sset) >= 3:
            for s in sset:
                shared_ip_flags.add(s)

    for dn, sset in device_to_students.items():
        if len(sset) >= 2:
            for s in sset:
                shared_device_flags.add(s)

    scores = {}
    for s in student_counts:
        score = 100
        if s in fast_flags: score -= 25
        if s in dup_flags: score -= 20
        if s in shared_ip_flags: score -= 40
        if student_counts[s] >= 3: score -= 10
        if s in out_of_window: score -= 15
        if s in burst_flags: score -= 10
        if s in shared_device_flags: score -= 50
        if score < 0: score = 0
        scores[s] = score

    results = []
    for s, sc in scores.items():
        flags = []
        if s in fast_flags: flags.append("fast")
        if s in dup_flags: flags.append("dup")
        if s in shared_ip_flags: flags.append("shared_ip")
        if s in shared_device_flags: flags.append("shared_device")
        if s in out_of_window: flags.append("out_of_window")
        if s in burst_flags: flags.append("burst")
        results.append((s, sc, "|".join(flags)))

    # 점수 오름차순, 학번 정렬
    results.sort(key=lambda x: (x[1], str(x[0])))

    # 필터링(옵션)
    if min_score > 0:
        results = [r for r in results if r[1] <= min_score]

    data = _csv_bytes(
        rows=[["student_id","score","flags"]] + [[sid, score, flags] for (sid, score, flags) in results],
        header=[],
        encoding="cp949"
    )
    return Response(
        content=data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="anomaly_{session_id}.csv"'}
    )

# =========================
# 라우트: 세션/대시보드/내보내기 등
# =========================
@app.on_event("startup")
async def on_startup():
    init_db()
    migrate_db()

@app.get("/", response_class=HTMLResponse)
async def index():
    html = open(os.path.join(os.path.dirname(__file__), "../frontend/index.html"), "r", encoding="utf-8").read()
    return HTMLResponse(html)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    html = open(os.path.join(os.path.dirname(__file__), "../frontend/dashboard.html"), "r", encoding="utf-8").read()
    return HTMLResponse(html)

@app.post("/api/session/start")
async def api_session_start(request: Request):
    """
    세션 시작: 바디가 없거나 형식이 엉켜도 안전하게 동작하도록 처리.
    기본 2시간.
    """
    # 바디 안전 파싱
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}

    try:
        hours = int(payload.get("hours", 2) or 2)
    except Exception:
        hours = 2
    if hours <= 0:
        hours = 2

    conn = db()
    cur = conn.cursor()
    start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    end = (datetime.now() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        "INSERT INTO sessions(class_id, start_time, end_time) VALUES(?,?,?)",
        ("CLS101", start, end)
    )
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    # ▼ 새 세션 스냅샷(빈 파일 포함) 생성
    snapshot_session_csvs(sid)
    return {"session_id": sid, "start_time": start, "end_time": end}

@app.get("/api/session/current")
async def api_current_session():
    sid = current_session_id()
    if not sid:
        raise HTTPException(status_code=404, detail="no active session")
    return {"session_id": sid}

# -------------------------
# 체크인 처리 (JWT만 허용)
# -------------------------
@app.post("/api/attendance/check-in")
async def api_check_in(data: dict, request: Request):
    sid = int(data.get("session_id", 0))
    student_id = str(data.get("student_id", "")).strip()
    token = str(data.get("token", "")).strip()   # 이제 '폼 토큰'이 들어옵니다
    device_name = str(data.get("device_name", "")).strip()

    if not sid or not student_id or not token:
        raise HTTPException(status_code=400, detail="invalid payload")

    now_epoch = int(time.time())

    # ✅ 1) 폼 토큰 우선 검증
    ft = FORM_TOKENS.get(token)
    if ft:
        # 만료/세션 불일치 확인
        if now_epoch > ft["exp"]:
            # 만료된 폼 토큰은 제거
            FORM_TOKENS.pop(token, None)
            raise HTTPException(status_code=400, detail="form token expired")
        if int(ft["sid"]) != sid:
            raise HTTPException(status_code=400, detail="session mismatch")

        # 1회용으로 사용 후 즉시 폐기 (대리출석 방지)
        FORM_TOKENS.pop(token, None)

        qr_generated_at = ft["issued_at"]  # 📌 페이지 진입 시각을 QR 생성시각으로 기록
    else:
        # ✅ 2) (옵션) 구형/백업: 예전 DB token(회전형)을 여전히 허용하려면 유지
        vt = valid_token(sid, token)
        if not vt:
            raise HTTPException(status_code=400, detail="invalid or expired token")
        qr_generated_at = vt["generated_at"]

    ip = client_ip(request)
    ua = request.headers.get("user-agent", "")
    if not device_name:
        device_name = ua[:64]

    conn = db()
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        "INSERT INTO attendance_logs(session_id, student_id, checked_at, ip, user_agent, token, qr_generated_at, anomaly_flags, device_name) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (sid, student_id, now, ip, ua, token, qr_generated_at, "", device_name)
    )
    conn.commit()
    conn.close()
    snapshot_session_csvs(sid)
    return {"ok": True}

# -------------------------
# 최근 출석/메일/내보내기 (원본 로직 유지)
# -------------------------
@app.get("/api/attendance/recent")
async def api_attendance_recent(days: int = 14, limit: int = 50):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT session_id, student_id, checked_at, device_name, ip
        FROM attendance_logs
        WHERE date(checked_at) >= ?
        ORDER BY id DESC
        LIMIT ?
    """, (cutoff, limit))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"logs": rows}

@app.get("/api/sessions")
async def api_sessions(limit: int = 20):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id, class_id, start_time, end_time FROM sessions ORDER BY start_time DESC LIMIT ?", (limit,))
    rows = cur.fetchall(); conn.close()
    out = []
    for r in rows:
        out.append({"id": r["id"], "class_id": r["class_id"], "start_time": r["start_time"], "end_time": r["end_time"]})
    return {"sessions": out}

# --- 세션별 출석/공결 조회 API (대시보드가 사용) -----------------------------

@app.get("/api/attendance/session/{session_id}/list")
async def api_attendance_list(session_id: int):
    """
    세션별 출석 로그 목록.
    세션이 없어도 200으로 빈 목록을 반환(대시보드 오류 방지).
    """
    conn = db(); cur = conn.cursor()
    # 세션 존재 확인 (없어도 에러 대신 빈 목록)
    cur.execute("SELECT 1 FROM sessions WHERE id=?", (session_id,))
    _ = cur.fetchone()

    cur.execute(
        "SELECT student_id, checked_at, ip, device_name "
        "FROM attendance_logs WHERE session_id=? ORDER BY id ASC",
        (session_id,)
    )
    rows = cur.fetchall()
    conn.close()

    logs = [
        {
            "student_id": r["student_id"],
            "checked_at": r["checked_at"],
            "ip": r["ip"],
            "device_name": r["device_name"],
        }
        for r in rows
    ]
    return {"session_id": session_id, "logs": logs}


@app.get("/api/excuses/session/{session_id}")
async def api_excuses_session(session_id: int):
    """
    세션 날짜에 해당하는 공결(이메일) 내역.
    세션이 없으면 빈 결과 반환.
    """
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT start_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()

    # 세션 없으면 빈 값
    if not srow:
        conn.close()
        return {"session_id": session_id, "session_date": None, "excuses": []}

    session_date = srow["start_time"][:10]
    cur.execute(
        "SELECT student_id, excuse_type, evidence_ok, notes "
        "FROM email_excuses WHERE session_date=? ORDER BY id ASC",
        (session_date,)
    )
    rows = cur.fetchall()
    conn.close()

    excuses = [
        {
            "student_id": r["student_id"],
            "excuse_type": r["excuse_type"],
            "evidence_ok": bool(r["evidence_ok"]),
            "notes": r["notes"] or "",
        }
        for r in rows
    ]
    return {"session_id": session_id, "session_date": session_date, "excuses": excuses}

@app.get("/api/export/attendance/recent.csv")
async def api_export_attendance_recent(days: int = 14):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT session_id, student_id, checked_at, ip, device_name, token, qr_generated_at, anomaly_flags
        FROM attendance_logs
        WHERE date(checked_at) >= ?
        ORDER BY session_id ASC, id ASC
    """, (cutoff,))
    rows = cur.fetchall(); conn.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["session_id","student_id","checked_at","ip","device_name","token","qr_generated_at","anomaly_flags"])
    for r in rows:
        w.writerow([r["session_id"], r["student_id"], r["checked_at"], r["ip"] or "", r["device_name"] or "", r["token"] or "", r["qr_generated_at"] or "", r["anomaly_flags"] or ""])
    data = buf.getvalue()
    return Response(content=data, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="attendance_recent_{days}d.csv"'})

@app.get("/api/export/session/{session_id}/attendance.csv")
async def api_export_attendance_csv(session_id: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT student_id, checked_at, ip, device_name, token, qr_generated_at, anomaly_flags FROM attendance_logs WHERE session_id=? ORDER BY id ASC", (session_id,))
    rows = cur.fetchall(); conn.close()
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["student_id","checked_at","ip","device_name","token","qr_generated_at","anomaly_flags"])
    for r in rows:
        w.writerow([r["student_id"], r["checked_at"], r["ip"], r["device_name"], r["token"], r["qr_generated_at"], r["anomaly_flags"] or ""])
    data = buf.getvalue()
    return Response(content=data, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="attendance_{session_id}.csv"'})

@app.get("/api/export/excuses/recent.csv")
async def api_export_excuses_recent(days: int = 14, enc: str = "cp949"):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT student_id, session_date, excuse_type, evidence_ok, notes
        FROM email_excuses
        WHERE session_date >= ?
        ORDER BY session_date ASC, id ASC
    """, (cutoff,))
    rows = cur.fetchall(); conn.close()
    data = _csv_bytes(
        rows=[[r["session_date"], r["student_id"], r["excuse_type"], int(r["evidence_ok"] or 0), _sanitize_notes(r["notes"])] for r in rows],
        header=["session_date","student_id","excuse_type","evidence_ok","notes"],
        encoding=enc
    )
    return Response(content=data, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="excuses_recent_{days}d.csv"'})

@app.get("/api/export/session/{session_id}/excuses.csv")
async def api_export_excuses_csv(session_id: int, enc: str = "cp949"):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT start_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")
    d = srow["start_time"][:10]
    cur.execute("""
        SELECT student_id, excuse_type, evidence_ok, notes
        FROM email_excuses
        WHERE session_date=?
        ORDER BY id ASC
    """, (d,))
    rows = cur.fetchall(); conn.close()
    data = _csv_bytes(
        rows=[[d, r["student_id"], r["excuse_type"], int(r["evidence_ok"] or 0), _sanitize_notes(r["notes"])] for r in rows],
        header=["session_date","student_id","excuse_type","evidence_ok","notes"],
        encoding=enc
    )
    return Response(content=data, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="excuses_{session_id}.csv"'})

# -------------------------
# 이상치/점수 (최신 버전만 유지)
# -------------------------
@app.get("/api/anomaly/session/{session_id}")
async def api_anomaly(session_id: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT start_time, end_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")
    s_start = datetime.strptime(srow["start_time"], "%Y-%m-%d %H:%M:%S")
    s_end = datetime.strptime(srow["end_time"], "%Y-%m-%d %H:%M:%S")

    cur.execute("SELECT student_id, checked_at, ip, qr_generated_at, device_name FROM attendance_logs WHERE session_id=? ORDER BY id ASC", (session_id,))
    rows = cur.fetchall(); conn.close()

    ip_to_students = {}
    device_to_students = {}
    student_counts = {}
    fast_flags = set()
    dup_flags = set()
    shared_ip_flags = set()
    shared_device_flags = set()
    out_of_window = set()
    burst_flags = set()
    seen = set()
    prev_by_student = {}

    for r in rows:
        k = (r["student_id"], r["ip"], r["checked_at"])
        student_counts[r["student_id"]] = student_counts.get(r["student_id"], 0) + 1

        ip_to_students.setdefault(r["ip"], set()).add(r["student_id"])
        dn = (r["device_name"] or "").strip()
        if dn:
            device_to_students.setdefault(dn, set()).add(r["student_id"])

        ga = datetime.strptime(r["qr_generated_at"], "%Y-%m-%d %H:%M:%S")
        ca = datetime.strptime(r["checked_at"], "%Y-%m-%d %H:%M:%S")

        if (ca - ga).total_seconds() < 2:
            fast_flags.add(r["student_id"])
        if k in seen:
            dup_flags.add(r["student_id"])
        seen.add(k)

        if ca < s_start or ca > s_end:
            out_of_window.add(r["student_id"])

        if r["student_id"] in prev_by_student:
            prev = prev_by_student[r["student_id"]]
            if (ca - prev).total_seconds() <= 5:
                burst_flags.add(r["student_id"])
        prev_by_student[r["student_id"]] = ca

    for ip, sset in ip_to_students.items():
        if len(sset) >= 3:
            for s in sset:
                shared_ip_flags.add(s)

    for dn, sset in device_to_students.items():
        if len(sset) >= 2:
            for s in sset:
                shared_device_flags.add(s)

    scores = {}
    for s in student_counts:
        score = 100
        if s in fast_flags: score -= 25
        if s in dup_flags: score -= 20
        if s in shared_ip_flags: score -= 40
        if student_counts[s] >= 3: score -= 10
        if s in out_of_window: score -= 15
        if s in burst_flags: score -= 10
        if s in shared_device_flags: score -= 50
        if score < 0: score = 0
        scores[s] = score

    out = []
    for s in sorted(scores.keys()):
        flags = []
        if s in fast_flags: flags.append("fast")
        if s in dup_flags: flags.append("dup")
        if s in shared_ip_flags: flags.append("shared_ip")
        if s in shared_device_flags: flags.append("shared_device")
        if s in out_of_window: flags.append("out_of_window")
        if s in burst_flags: flags.append("burst")
        out.append({"student_id": s, "score": scores[s], "flags": flags})
    return {"session_id": session_id, "results": out}

# -------------------------
# Gmail 연동/공결 적용 (기존 유지)
# -------------------------
@app.post("/api/excuses/gmail/ingest")
async def api_gmail_ingest(query: str = None, days: int = 30):
    import importlib.util, traceback
    try:
        p = os.path.join(os.path.dirname(__file__), "gmail_ingest.py")
        spec = importlib.util.spec_from_file_location("gmail_ingest", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        default_q = '(subject:공결 OR 공결 OR 진단서 OR 참가확인서)'
        q = default_q if (query is None) else query
        result = mod.run(q, days)
        found = upserted = sid_missing = 0
        if isinstance(result, tuple):
            if len(result) >= 1: found = result[0] or 0
            if len(result) >= 2: upserted = result[1] or 0
            if len(result) >= 3: sid_missing = result[2] or 0
        elif isinstance(result, int):
            upserted = result
        return {"ok": True, "query": q, "days": days, "found": found, "upserted": upserted, "sid_missing": sid_missing}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e), "trace": traceback.format_exc()})

def apply_excuses(session_id: int) -> int:
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT start_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        return 0
    d = srow["start_time"][:10]
    cur.execute("SELECT student_id, excuse_type, evidence_ok, ai_label, ai_confidence, ai_reason, notes FROM email_excuses WHERE session_date=?", (d,))
    rows = cur.fetchall()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    n = 0
    for r in rows:
        if (r["excuse_type"] in ("공결", "병결")) and int(r["evidence_ok"] or 0) == 1:
            cur.execute("""
              INSERT INTO excused_attendance(session_id, student_id, excuse_type, evidence_ok, notes, source, created_at)
              VALUES(?,?,?,?,?,?,?)
              ON CONFLICT(session_id, student_id) DO UPDATE SET
                excuse_type=excluded.excuse_type,
                evidence_ok=excluded.evidence_ok,
                notes=excluded.notes
            """, (session_id, r["student_id"], r["excuse_type"], 1, (r["notes"] or "")[:200],
                  f"gmail+gemini({(r['ai_label'] or '')}/{(r['ai_confidence'] or 0)})", now))
            n += 1
    conn.commit(); conn.close()
    return n

@app.post("/api/excuses/apply")
async def api_excuses_apply(data: dict):
    sid = int(data.get("session_id", 0)) or current_session_id()
    if not sid:
        raise HTTPException(status_code=400, detail="no session")
    n = apply_excuses(sid)
    snapshot_session_csvs(sid)
    return {"ok": True, "applied": n}

# -------------------------
# 메일/최근 공결 조회 (그대로)
# -------------------------
@app.get("/api/excuses/recent")
async def api_excuses_recent(days: int = 14, limit: int = 200):
    cutoff = (datetime.now() - timedelta(days=days)).date().isoformat()
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT id, student_id, session_date, excuse_type, evidence_ok, notes
        FROM email_excuses
        WHERE session_date >= ?
        ORDER BY id DESC
        LIMIT ?
    """, (cutoff, limit))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"rows": rows}

# -------------------------
# 수동 공결 upsert(그대로)
# -------------------------
@app.post("/api/excuses/upsert")
async def api_excuse_upsert(data: dict):
    student_id = str(data.get("student_id","")).strip()
    session_date = str(data.get("session_date","")).strip()
    excuse_type = str(data.get("excuse_type","")).strip()
    evidence_ok = int(bool(data.get("evidence_ok", False)))
    notes = str(data.get("notes","")).strip()
    if not student_id or not session_date or not excuse_type:
        raise HTTPException(status_code=400, detail="invalid payload")
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id FROM sessions WHERE date(start_time)=?", (session_date,))
    sids = [r["id"] for r in cur.fetchall()]
    conn.close()
    for sid in sids:
        snapshot_session_csvs(sid)
    return {"ok": True}

# ====== [NEW] 의심 학생만 반환하는 엔드포인트 ======
@app.get("/api/anomaly/session/{session_id}/suspects")
async def api_anomaly_suspects(session_id: int):
    """
    점수 없이 '의심 사유'만 모아서 반환.
    - 동일 IP 3명 이상
    - 동일 기기(기기명) 2명 이상
    - QR 생성 후 2초 내 초고속 접속
    - 세션 시간 밖 접속
    - 5초 이내 연속 접속
    - 완전 동일 로그(중복)
    """
    conn = db()
    cur = conn.cursor()

    # 세션 시간
    cur.execute("SELECT start_time, end_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")

    s_start = datetime.strptime(srow["start_time"], "%Y-%m-%d %H:%M:%S")
    s_end   = datetime.strptime(srow["end_time"], "%Y-%m-%d %H:%M:%S")

    # 로그 수집 (기기명 포함)
    cur.execute("""
        SELECT student_id, checked_at, ip, qr_generated_at, device_name
        FROM attendance_logs
        WHERE session_id=?
        ORDER BY id ASC
    """, (session_id,))
    rows = cur.fetchall()
    conn.close()

    ip_to_students = {}
    device_to_students = {}
    seen = set()
    prev_by_student = {}

    # 플래그 세트
    fast_flags = set()           # QR 생성 2초 내 접속
    dup_flags = set()            # 완전 동일 로그 중복
    shared_ip_flags = set()      # 동일 IP 3명+
    shared_device_flags = set()  # 동일 기기 2명+
    out_of_window = set()        # 세션 시간 밖 접속
    burst_flags = set()          # 5초 이내 연속 접속

    for r in rows:
        k = (r["student_id"], r["ip"], r["checked_at"])
        ip_to_students.setdefault(r["ip"], set()).add(r["student_id"])

        dn = (r["device_name"] or "").strip()
        if dn:
            device_to_students.setdefault(dn, set()).add(r["student_id"])

        # 시간 파싱
        ga = datetime.strptime(r["qr_generated_at"], "%Y-%m-%d %H:%M:%S")
        ca = datetime.strptime(r["checked_at"], "%Y-%m-%d %H:%M:%S")

        # 1) 너무 빠른 접속(봇/공유 가능성)
        if (ca - ga).total_seconds() < 2:
            fast_flags.add(r["student_id"])

        # 2) 완전 동일 로그
        if k in seen:
            dup_flags.add(r["student_id"])
        seen.add(k)

        # 3) 세션 시간 바깥
        if ca < s_start or ca > s_end:
            out_of_window.add(r["student_id"])

        # 4) 5초 이내 연속 접속(여러 장치/스크립트 시도)
        sid = r["student_id"]
        if sid in prev_by_student:
            prev = prev_by_student[sid]
            if (ca - prev).total_seconds() <= 5:
                burst_flags.add(sid)
        prev_by_student[sid] = ca

    # 5) 동일 IP 3명 이상 사용
    for ip, sset in ip_to_students.items():
        if len(sset) >= 3:
            for s in sset:
                shared_ip_flags.add(s)

    # 6) 동일 기기에서 2명 이상(기기명으로 클러스터링)
    for dn, sset in device_to_students.items():
        if len(sset) >= 2:
            for s in sset:
                shared_device_flags.add(s)

    # 학생별 사유 모으기
    reasons_map = {}
    def add_reason(sid, msg):
        reasons_map.setdefault(sid, set()).add(msg)

    for s in fast_flags:
        add_reason(s, "QR 생성 후 2초 내 접속")
    for s in dup_flags:
        add_reason(s, "중복 로그")
    for s in shared_ip_flags:
        add_reason(s, "동일 IP 다수(3명 이상)")
    for s in shared_device_flags:
        add_reason(s, "동일 기기 사용(2명 이상)")
    for s in out_of_window:
        add_reason(s, "세션 시간 외 접속")
    for s in burst_flags:
        add_reason(s, "5초 이내 반복 접속")

    suspects = []
    for sid, reasons in reasons_map.items():
        suspects.append({
            "student_id": sid,
            "reasons": sorted(list(reasons))
        })

    # 정렬: 사유 개수 많은 순, 학번순
    suspects.sort(key=lambda x: (-len(x["reasons"]), str(x["student_id"])))
    return {"session_id": session_id, "suspects": suspects}

# === [ADD] 현재 진행중인 세션을 바로 분석하는 엔드포인트 ===
@app.get("/api/anomaly/current")
async def api_anomaly_current():
    sid = current_session_id()
    if not sid:
        raise HTTPException(status_code=404, detail="no active session")
    # 이미 있는 함수 재사용
    return await api_anomaly(session_id=sid)

def _write_csv_utf8bom(header, rows, path):
    """UTF-8 BOM으로 파일 저장(엑셀 호환)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
        w.writerow(header)
        for r in rows:
            w.writerow(r)

def _session_export_dir(session_id: int, session_date: str) -> str:
    # 예: exports/session_15_2025-10-23
    safe = f"session_{session_id}_{session_date}"
    return os.path.join(EXPORT_ROOT, safe)

def snapshot_session_csvs(session_id: int):
    """세션별 스냅샷 CSV 두 개(출석/공결)를 exports/ 아래 갱신 저장."""
    conn = db(); cur = conn.cursor()

    # 세션 날짜 알아내기
    cur.execute("SELECT start_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        return
    session_date = srow["start_time"][:10]
    outdir = _session_export_dir(session_id, session_date)

    # 출석 로그 스냅샷
    cur.execute("""
        SELECT student_id, checked_at, ip, device_name, token, qr_generated_at, anomaly_flags
        FROM attendance_logs
        WHERE session_id=?
        ORDER BY id ASC
    """, (session_id,))
    att_rows = cur.fetchall()
    _write_csv_utf8bom(
        ["student_id","checked_at","ip","device_name","token","qr_generated_at","anomaly_flags"],
        [[r["student_id"], r["checked_at"], r["ip"] or "", r["device_name"] or "", r["token"] or "", r["qr_generated_at"] or "", r["anomaly_flags"] or ""] for r in att_rows],
        os.path.join(outdir, "attendance.csv")
    )

    # 공결 스냅샷(세션 날짜 기준)
    cur.execute("""
        SELECT student_id, excuse_type, evidence_ok, notes
        FROM email_excuses
        WHERE session_date=?
        ORDER BY id ASC
    """, (session_date,))
    exc_rows = cur.fetchall()
    _write_csv_utf8bom(
        ["session_date","student_id","excuse_type","evidence_ok","notes"],
        [[session_date, r["student_id"], r["excuse_type"], int(r["evidence_ok"] or 0), _sanitize_notes(r["notes"])] for r in exc_rows],
        os.path.join(outdir, "excuses.csv")
    )

    conn.close()

# -------------------------
# 메인
# -------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
