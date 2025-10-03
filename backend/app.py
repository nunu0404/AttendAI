import os
import sqlite3
import asyncio
import secrets
import io
import base64
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, HTTPException, Body
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import qrcode
from fastapi import Response
import csv, io

app = FastAPI()
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "../frontend/static")), name="static")
DB_PATH = os.path.join(os.path.dirname(__file__), "attendai.db")
QR_PERIOD_SECONDS = 15

@app.get("/api/anomaly/session/{session_id}")
async def api_anomaly(session_id: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT start_time, end_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")
    s_start = datetime.strptime(srow["start_time"], "%Y-%m-%d %H:%M:%S")
    s_end = datetime.strptime(srow["end_time"], "%Y-%m-%d %H:%M:%S")

    cur.execute("SELECT student_id, checked_at, ip, qr_generated_at FROM attendance_logs WHERE session_id=? ORDER BY id ASC", (session_id,))
    rows = cur.fetchall()
    conn.close()

    ip_to_students = {}
    student_counts = {}
    fast_flags = set()
    dup_flags = set()
    shared_ip_flags = set()
    out_of_window = set()
    burst_flags = set()
    seen = set()

    prev_by_student = {}

    for r in rows:
        k = (r["student_id"], r["ip"], r["checked_at"])
        student_counts[r["student_id"]] = student_counts.get(r["student_id"], 0) + 1
        ip_to_students.setdefault(r["ip"], set()).add(r["student_id"])

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

    scores = {}
    for s in student_counts:
        score = 100
        if s in fast_flags:
            score -= 25
        if s in dup_flags:
            score -= 20
        if s in shared_ip_flags:
            score -= 40
        if student_counts[s] >= 3:
            score -= 10
        if s in out_of_window:
            score -= 15
        if s in burst_flags:
            score -= 10
        if score < 0:
            score = 0
        scores[s] = score

    out = []
    for s in sorted(scores.keys()):
        flags = []
        if s in fast_flags: flags.append("fast")
        if s in dup_flags: flags.append("dup")
        if s in shared_ip_flags: flags.append("shared_ip")
        if s in out_of_window: flags.append("out_of_window")
        if s in burst_flags: flags.append("burst")
        out.append({"student_id": s, "score": scores[s], "flags": flags})
    return {"session_id": session_id, "results": out}

@app.get("/api/excuses/session/{session_id}")
async def api_excuses_session(session_id: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT start_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")
    d = srow["start_time"][:10]
    cur.execute(
        "SELECT student_id, excuse_type, evidence_ok, notes "
        "FROM email_excuses WHERE session_date=? ORDER BY id ASC",
        (d,)
    )
    rows = cur.fetchall()
    conn.close()
    return {
        "session_id": session_id,
        "session_date": d,
        "excuses": [
            {
                "student_id": r["student_id"],
                "excuse_type": r["excuse_type"],
                "evidence_ok": bool(r["evidence_ok"]),
                "notes": r["notes"] or ""
            } for r in rows
        ]
    }

@app.post("/api/excuses/gmail/ingest")
async def api_gmail_ingest(query: str = None, days: int = 14):
    import importlib.util, os
    p = os.path.join(os.path.dirname(__file__), "gmail_ingest.py")
    spec = importlib.util.spec_from_file_location("gmail_ingest", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # None 인 경우만 기본 쿼리 적용. ''(빈 문자열)은 "전체"로 해석.
    default_q = '(subject:공결 OR 공결 OR 진단서 OR 참가확인서)'
    q = default_q if (query is None) else query

    mod.run(q, days)
    return {"ok": True, "query": q, "days": days}

@app.get("/api/sessions")
async def api_sessions(limit: int = 20):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, class_id, start_time, end_time FROM sessions ORDER BY start_time DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "class_id": r["class_id"],
            "start_time": r["start_time"],
            "end_time": r["end_time"]
        })
    return {"sessions": out}

@app.get("/api/export/session/{session_id}/attendance.csv")
async def api_export_attendance_csv(session_id: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT start_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")
    cur.execute("SELECT student_id, checked_at, ip, device_name, token, qr_generated_at, anomaly_flags FROM attendance_logs WHERE session_id=? ORDER BY id ASC", (session_id,))
    rows = cur.fetchall()
    conn.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["student_id","checked_at","ip","device_name","token","qr_generated_at","anomaly_flags"])
    for r in rows:
        w.writerow([r["student_id"], r["checked_at"], r["ip"], r["device_name"], r["token"], r["qr_generated_at"], r["anomaly_flags"] or ""])
    data = buf.getvalue()
    return Response(content=data, media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="attendance_{session_id}.csv"'})

@app.get("/api/export/session/{session_id}/excuses.csv")
async def api_export_excuses_csv(session_id: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT start_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")
    d = srow["start_time"][:10]
    cur.execute("SELECT student_id, excuse_type, evidence_ok, notes FROM email_excuses WHERE session_date=? ORDER BY id ASC", (d,))
    rows = cur.fetchall()
    conn.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["session_date","student_id","excuse_type","evidence_ok","notes"])
    for r in rows:
        w.writerow([d, r["student_id"], r["excuse_type"], int(r["evidence_ok"]), r["notes"] or ""])
    data = buf.getvalue()
    return Response(content=data, media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="excuses_{session_id}.csv"'})

@app.post("/api/session/start")
async def api_session_start(hours: int = Body(2)):
    conn = db()
    cur = conn.cursor()
    start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    end = (datetime.now() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO sessions(class_id, start_time, end_time) VALUES(?,?,?)",
                ("CLS101", start, end))
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    return {"session_id": sid, "start_time": start, "end_time": end}

@app.get("/api/attendance/session/{session_id}/list")
async def api_attendance_list(session_id: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT student_id, checked_at, ip, device_name FROM attendance_logs WHERE session_id=? ORDER BY id ASC", (session_id,))
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({"student_id": r["student_id"], "checked_at": r["checked_at"], "ip": r["ip"], "device_name": r["device_name"]})
    return {"session_id": session_id, "logs": out}


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
    cur.execute("CREATE TABLE IF NOT EXISTS qr_tokens(id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, token TEXT, generated_at TEXT, valid_until TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS attendance_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, student_id TEXT, checked_at TEXT, ip TEXT, user_agent TEXT, token TEXT, qr_generated_at TEXT, anomaly_flags TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS email_excuses(id INTEGER PRIMARY KEY AUTOINCREMENT, student_id TEXT, session_date TEXT, excuse_type TEXT, evidence_ok INTEGER, notes TEXT)")
    conn.commit()
    cur.execute("INSERT OR IGNORE INTO classes(id,name) VALUES(?,?)", ("CLS101","Default Class"))
    conn.commit()
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
    try:
        cur.execute("ALTER TABLE attendance_logs ADD COLUMN device_name TEXT")
        conn.commit()
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE email_excuses ADD COLUMN msg_id TEXT")
        conn.commit()
    except Exception:
        pass
    try:
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_email_excuses_msgid ON email_excuses(msg_id)")
        conn.commit()
    except Exception:
        pass
    conn.close()


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

def get_or_rotate_token(session_id):
    conn = db()
    cur = conn.cursor()
    now = datetime.now()
    cur.execute("SELECT id, token, generated_at, valid_until FROM qr_tokens WHERE session_id=? ORDER BY id DESC LIMIT 1", (session_id,))
    row = cur.fetchone()
    if row:
        gu = datetime.strptime(row["valid_until"], "%Y-%m-%d %H:%M:%S")
        if now <= gu:
            conn.close()
            return row["token"], row["generated_at"], row["valid_until"]
    token = secrets.token_urlsafe(10)
    ga = now
    vu = now + timedelta(seconds=QR_PERIOD_SECONDS)
    cur.execute("INSERT INTO qr_tokens(session_id, token, generated_at, valid_until) VALUES(?,?,?,?)", (session_id, token, ga.strftime("%Y-%m-%d %H:%M:%S"), vu.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    cur.execute("SELECT id, token, generated_at, valid_until FROM qr_tokens WHERE session_id=? ORDER BY id DESC LIMIT 1", (session_id,))
    row = cur.fetchone()
    conn.close()
    return row["token"], row["generated_at"], row["valid_until"]

def latest_token(session_id):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT token, generated_at, valid_until FROM qr_tokens WHERE session_id=? ORDER BY id DESC LIMIT 1", (session_id,))
    row = cur.fetchone()
    conn.close()
    return row

def valid_token(session_id, token):
    conn = db()
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("SELECT token, generated_at, valid_until FROM qr_tokens WHERE session_id=? AND token=? ORDER BY id DESC LIMIT 1", (session_id, token))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    if now > row["valid_until"]:
        return None
    return row

def client_ip(request: Request):
    xf = request.headers.get("x-forwarded-for")
    if xf:
        return xf.split(",")[0].strip()
    return request.client.host

@app.on_event("startup")
async def on_startup():
    init_db()
    migrate_db()

@app.get("/", response_class=HTMLResponse)
async def index():
    html = open(os.path.join(os.path.dirname(__file__), "../frontend/index.html"), "r", encoding="utf-8").read()
    return HTMLResponse(html)

@app.get("/checkin", response_class=HTMLResponse)
async def checkin_page():
    html = open(os.path.join(os.path.dirname(__file__), "../frontend/checkin.html"), "r", encoding="utf-8").read()
    return HTMLResponse(html)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    html = open(os.path.join(os.path.dirname(__file__), "../frontend/dashboard.html"), "r", encoding="utf-8").read()
    return HTMLResponse(html)

@app.get("/api/session/current")
async def api_current_session():
    sid = current_session_id()
    if not sid:
        raise HTTPException(status_code=404, detail="no active session")
    return {"session_id": sid}

@app.get("/api/qr/current")
async def api_qr_current(session_id: int = None, request: Request = None):
    sid = session_id or current_session_id()
    if not sid:
        # 없으면 자동으로 새 세션 시작
        conn = db(); cur = conn.cursor()
        start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        end = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("INSERT INTO sessions(class_id, start_time, end_time) VALUES(?,?,?)",
                    ("CLS101", start, end))
        conn.commit()
        sid = cur.lastrowid
        conn.close()
    t, ga, vu = get_or_rotate_token(sid)
    return {"session_id": sid, "token": t, "generated_at": ga, "valid_until": vu}


@app.get("/api/qr/image")
async def api_qr_image(session_id: int = None, request: Request = None):
    sid = session_id or current_session_id()
    if not sid:
        raise HTTPException(status_code=404, detail="no active session")
    row = latest_token(sid)
    if not row:
        t, ga, vu = get_or_rotate_token(sid)
    else:
        t = row["token"]
    base = str(request.base_url).rstrip("/")
    url = f"{base}/checkin?session_id={sid}&token={t}"
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")

@app.post("/api/attendance/check-in")
async def api_check_in(data: dict, request: Request):
    sid = int(data.get("session_id", 0))
    student_id = str(data.get("student_id", "")).strip()
    token = str(data.get("token", "")).strip()
    device_name = str(data.get("device_name", "")).strip()

    if not sid or not student_id or not token:
        raise HTTPException(status_code=400, detail="invalid payload")

    vt = valid_token(sid, token)
    if not vt:
        raise HTTPException(status_code=400, detail="invalid or expired token")

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
        (sid, student_id, now, ip, ua, token, vt["generated_at"], "", device_name)
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/attendance/session/{session_id}/stats")
async def api_stats(session_id: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM attendance_logs WHERE session_id=?", (session_id,))
    c = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(DISTINCT student_id) AS d FROM attendance_logs WHERE session_id=?", (session_id,))
    d = cur.fetchone()["d"]
    conn.close()
    return {"session_id": session_id, "total_logs": c, "unique_students": d}

@app.post("/api/excuses/upsert")
async def api_excuse_upsert(data: dict):
    student_id = str(data.get("student_id","")).strip()
    session_date = str(data.get("session_date","")).strip()
    excuse_type = str(data.get("excuse_type","")).strip()
    evidence_ok = int(bool(data.get("evidence_ok", False)))
    notes = str(data.get("notes","")).strip()
    if not student_id or not session_date or not excuse_type:
        raise HTTPException(status_code=400, detail="invalid payload")
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM email_excuses WHERE student_id=? AND session_date=?", (student_id, session_date))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE email_excuses SET excuse_type=?, evidence_ok=?, notes=? WHERE id=?", (excuse_type, evidence_ok, notes, row["id"]))
    else:
        cur.execute("INSERT INTO email_excuses(student_id, session_date, excuse_type, evidence_ok, notes) VALUES(?,?,?,?,?)", (student_id, session_date, excuse_type, evidence_ok, notes))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.get("/api/anomaly/session/{session_id}")
async def api_anomaly(session_id: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT start_time, end_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")
    s_start = datetime.strptime(srow["start_time"], "%Y-%m-%d %H:%M:%S")
    s_end = datetime.strptime(srow["end_time"], "%Y-%m-%d %H:%M:%S")

    cur.execute("SELECT student_id, checked_at, ip, qr_generated_at, device_name FROM attendance_logs WHERE session_id=? ORDER BY id ASC", (session_id,))
    rows = cur.fetchall()
    conn.close()

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

    # 동일 IP에서 3명 이상
    for ip, sset in ip_to_students.items():
        if len(sset) >= 3:
            for s in sset:
                shared_ip_flags.add(s)

    # 동일 기기(device_name)에서 2명 이상이면 대리출석 의심
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
        if s in shared_device_flags: score -= 50  # 대리출석 강력 감점
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
