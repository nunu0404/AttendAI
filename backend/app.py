import os
import sqlite3
import asyncio
import secrets
import io
import base64
import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Optional
from collections.abc import Mapping, Iterable

from fastapi import FastAPI, Request, HTTPException, Body, Query
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
import qrcode
import csv
import time
import jwt
import json
import urllib.request
import shutil

# WebAuthn / FIDO2
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    CollectedClientData,
    AuthenticatorData,
)
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.features import webauthn_json_mapping
from urllib.parse import urlparse

webauthn_json_mapping.enabled = True

# =========================
# 환경/전역
# =========================
EXPORT_ROOT = os.path.join(os.path.dirname(__file__), "exports")
os.makedirs(EXPORT_ROOT, exist_ok=True)

QR_SECRET = os.getenv("QR_SECRET", "change-me")  # 운영에서는 환경변수로 지정
JWT_ALG = "HS256"
QR_NONCES: dict[int, dict[str, int]] = {}       # 세션별 nonce -> exp
LATEST_QR_TOKEN: dict[int, str] = {}            # 최신 QR JWT 문자열 캐시
FORM_TOKENS: dict[str, dict] = {}

FORM_TOKEN_TTL_SECONDS = 60  # 페이지 진입 후 1분 동안 제출 허용 (원하면 조정)

RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "AttendAI")
WEBAUTHN_STATE: dict[str, object] = {}

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip()
NGROK_PUBLIC_URL: Optional[str] = None
NGROK_LAST_CHECK: float = 0.0
NGROK_CHECK_INTERVAL: float = 15.0


def _parse_allowed_subnets(raw: str | None) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    if not raw:
        return networks
    items = raw.replace(";", ",").split(",")
    for item in items:
        candidate = item.strip()
        if not candidate:
            continue
        try:
            if "/" in candidate:
                network = ipaddress.ip_network(candidate, strict=False)
            else:
                network = ipaddress.ip_network(f"{candidate}/32", strict=False)
            networks.append(network)
        except ValueError:
            continue
    return networks


_raw_allowed = os.getenv("CHECKIN_ALLOWED_SUBNETS")
CHECKIN_ALLOWED_SUBNETS = _parse_allowed_subnets(_raw_allowed)

candidate_base = (os.getenv("CHECKIN_BASE_URL") or "").strip()
if candidate_base:
    if "://" not in candidate_base:
        candidate_base = f"http://{candidate_base}"
    CHECKIN_FORCED_BASE_URL = candidate_base.rstrip("/")
else:
    CHECKIN_FORCED_BASE_URL = None


app = FastAPI()
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(os.path.dirname(__file__), "../frontend/static")),
    name="static",
)
DB_PATH = os.path.join(os.path.dirname(__file__), "attendai.db")
QR_PERIOD_SECONDS = 15  # 표시용 기본 주기(대시보드 타이머와 맞추기)
try:
    QR_TOKEN_GRACE_SECONDS = max(0, int(os.getenv("QR_TOKEN_GRACE_SECONDS", "10")))
except ValueError:
    QR_TOKEN_GRACE_SECONDS = 10

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
        ai_reason TEXT,
        mail_time TEXT
    )""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS webauthn_credentials(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            credential_id BLOB NOT NULL,
            public_key  BLOB NOT NULL,
            sign_count  INTEGER DEFAULT 0,
            transports  TEXT,
            created_at  TEXT,
            UNIQUE(student_id, credential_id)
        )
    """)
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

    try:
        cur.execute("ALTER TABLE attendance_logs ADD COLUMN device_name TEXT")
        conn.commit()
    except Exception:
        pass

    for stmt in [
        "ALTER TABLE email_excuses ADD COLUMN msg_id TEXT",
        "ALTER TABLE email_excuses ADD COLUMN ai_label TEXT",
        "ALTER TABLE email_excuses ADD COLUMN ai_confidence REAL",
        "ALTER TABLE email_excuses ADD COLUMN ai_reason TEXT",
        "ALTER TABLE email_excuses ADD COLUMN mail_time TEXT",
    ]:
        try:
            cur.execute(stmt)
            conn.commit()
        except Exception:
            pass

    try:
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_email_excuses_msgid ON email_excuses(msg_id)")
        conn.commit()
    except Exception:
        pass

    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS webauthn_credentials(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                credential_id BLOB NOT NULL,
                public_key  BLOB NOT NULL,
                sign_count  INTEGER DEFAULT 0,
                transports  TEXT,
                created_at  TEXT,
                UNIQUE(student_id, credential_id)
            )
            """
        )
        conn.commit()
    except Exception:
        pass

    try:
        cur.execute(
            """
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
            """
        )
        conn.commit()
    except Exception:
        pass

    conn.close()


# =========================
# 공통 유틸
# =========================
def _has_column(cur, table: str, col: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any((row["name"] == col) for row in cur.fetchall())


def _b64u_decode(value):
    if value is None:
        return None
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("ascii")
    value = value.strip()
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception:
        return base64.b64decode(value + padding)

def _cbor_encode(value):
    if hasattr(cbor, "dumps"):
        return cbor.dumps(value)
    if hasattr(cbor, "encode"):
        return cbor.encode(value)
    raise AttributeError("python-fido2.cbor missing dumps/encode")


def _cbor_decode(data):
    if data is None:
        raise ValueError("no data")
    if isinstance(data, memoryview):
        data = data.tobytes()
    elif isinstance(data, str):
        s = data.strip()
        try:
            data = _b64u_decode(s)
        except Exception:
            try:
                import base64
                data = base64.b64decode(s)
            except Exception:
                data = s.encode("utf-8")
    elif not isinstance(data, (bytes, bytearray)):
        data = bytes(data)
    if hasattr(cbor, "loads"):
        return cbor.loads(data)
    return cbor.decode(data)



def _deserialize_public_key(value):
    if value is None:
        raise ValueError("missing public key")

    def as_dict(obj):
        if isinstance(obj, dict):
            return obj
        if hasattr(obj, "items"):
            try:
                return dict(obj)
            except Exception:
                pass
        return None

    maybe_dict = as_dict(value)
    if maybe_dict is not None:
        return CoseKey.parse(maybe_dict)

    raw = value
    if isinstance(raw, memoryview):
        raw = raw.tobytes()
    elif isinstance(raw, str):
        raw = raw.strip()
        try:
            parsed = json.loads(raw)
            maybe_dict = as_dict(parsed)
            if maybe_dict is not None:
                return CoseKey.parse(maybe_dict)
        except Exception:
            pass
        try:
            raw = _b64u_decode(raw)
        except Exception:
            try:
                raw = base64.b64decode(raw + "".join('=' for _ in range((4 - len(raw) % 4) % 4)))
            except Exception:
                raw = raw.encode("utf-8")
    elif not isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw)

    decoded = _cbor_decode(raw)
    if isinstance(decoded, (bytes, bytearray, memoryview)):
        decoded = _cbor_decode(decoded)

    maybe_dict = as_dict(decoded)
    if maybe_dict is not None:
        return CoseKey.parse(maybe_dict)

    raise ValueError("unsupported public key format")

class _StoredCredential:
    __slots__ = ("credential_id", "public_key", "sign_count", "transports")

    def __init__(self, credential_id, public_key, sign_count, transports=None):
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count
        self.transports = transports


def _b64u_if_bytes(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.urlsafe_b64encode(bytes(value)).rstrip(b"=").decode("ascii")
    return value


def _get_fido2_server(request: Request) -> Fido2Server:
    rp_id = (os.getenv("WEBAUTHN_RP_ID") or request.headers.get("host", "").split(":")[0]).strip() or RP_ID
    rp = PublicKeyCredentialRpEntity(id=rp_id, name=RP_NAME)
    return Fido2Server(rp)


def make_fido_server(request: Request) -> Fido2Server:
    host = request.url.hostname or RP_ID
    rp = PublicKeyCredentialRpEntity(id=host, name=RP_NAME)
    return Fido2Server(rp)


def upsert_credential(student_id: str, credential_id: bytes, public_key: bytes, sign_count: int, transports: Optional[str] = None):
    conn = db()
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        """
        INSERT INTO webauthn_credentials(student_id, credential_id, public_key, sign_count, transports, created_at)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(credential_id) DO UPDATE SET
          student_id=excluded.student_id,
          public_key=excluded.public_key,
          sign_count=excluded.sign_count,
          transports=excluded.transports
        """,
        (student_id, credential_id, public_key, sign_count, transports, now),
    )
    conn.commit()
    conn.close()


def get_credentials_by_student(student_id: str):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT credential_id, public_key, sign_count, transports FROM webauthn_credentials WHERE student_id=?",
        (student_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def _load_credentials_for_user(student_id: str):
    rows = get_credentials_by_student(student_id)
    creds = []
    for r in rows:
        cred_id = r["credential_id"]
        if isinstance(cred_id, memoryview):
            cred_id = cred_id.tobytes()
        public_key_bytes = r["public_key"]
        if isinstance(public_key_bytes, memoryview):
            public_key_bytes = public_key_bytes.tobytes()
        creds.append({
            "credential_id": cred_id,
            "public_key": public_key_bytes,
            "sign_count": r["sign_count"],
            "transports": r["transports"],
        })
    return creds


def _sanitize_notes(s: str) -> str:
    return (s or "").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

def _parse_local_dt(value) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None

def _merge_notes(*values: str) -> str:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value:
            continue
        parts = [p.strip() for p in str(value).split(";")]
        for part in parts:
            if part and part not in seen:
                ordered.append(part)
                seen.add(part)
    return "; ".join(ordered)


def _extract_ip_candidates(request: Request | None) -> list[str]:
    if request is None:
        return []
    candidates: list[str] = []
    xf = request.headers.get("x-forwarded-for") if hasattr(request, "headers") else None
    if xf:
        for part in xf.split(","):
            ip = part.strip()
            if ip:
                candidates.append(ip)
    host = getattr(request.client, "host", None)
    if host:
        candidates.append(host)
    return candidates


def _is_ip_allowed(ip: str | None) -> bool:
    if not CHECKIN_ALLOWED_SUBNETS:
        return True
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    candidates = [addr]
    if addr.version == 6 and getattr(addr, "ipv4_mapped", None):
        candidates.append(addr.ipv4_mapped)  # type: ignore[arg-type]
    elif addr.version == 4:
        try:
            candidates.append(ipaddress.ip_address(f"::ffff:{addr}"))
        except ValueError:
            pass

    for candidate in candidates:
        for net in CHECKIN_ALLOWED_SUBNETS:
            try:
                if candidate in net:
                    return True
            except TypeError:
                # IPv4 network vs IPv6 addr or vice versa
                continue
    return False


def _is_request_allowed_for_checkin(request: Request | None) -> bool:
    if not CHECKIN_ALLOWED_SUBNETS:
        return True
    for ip in _extract_ip_candidates(request):
        if _is_ip_allowed(ip):
            return True
    return False


def _require_checkin_network(request: Request | None):
    if not CHECKIN_ALLOWED_SUBNETS:
        return
    if not _is_request_allowed_for_checkin(request):
        raise HTTPException(status_code=403, detail="network not allowed")


def _refresh_sessions_for_dates(dates: Iterable[str]) -> list[int]:
    normalized: set[str] = set()
    for value in dates or []:
        if not value:
            continue
        text = str(value).strip()
        if not text:
            continue
        normalized.add(text[:10])
    if not normalized:
        return []

    conn = db(); cur = conn.cursor()
    refreshed: set[int] = set()
    try:
        for session_date in normalized:
            cur.execute("SELECT id FROM sessions WHERE date(start_time)=?", (session_date,))
            for row in cur.fetchall() or []:
                session_id = int(row["id"])
                if session_id not in refreshed:
                    snapshot_session_csvs(session_id)
                    refreshed.add(session_id)
    finally:
        conn.close()
    return sorted(refreshed)

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
    ips = _extract_ip_candidates(request)
    return ips[0] if ips else None

def _normalize_base_url(raw: str | None) -> Optional[str]:
    if not raw:
        return None
    value = raw.strip()
    if not value:
        return None
    low = value.lower()
    if low in {"http", "https"}:
        return None

    # Normalize slashes (handle cases like https//domain or http:\\domain)
    value = value.replace("\\", "/")
    value = re.sub(r"(?i)(https?)(:)?/{1,}", lambda m: f"{m.group(1).lower()}://", value)

    # Collapse duplicated schemes (https://https://domain -> https://domain)
    while True:
        replaced = (
            value.replace("https://https://", "https://")
            .replace("http://http://", "http://")
            .replace("https://http://", "https://")
            .replace("http://https://", "https://")
        )
        if replaced == value:
            break
        value = replaced

    if "://" not in value:
        value = value.lstrip("/")
        if not value:
            return None
        value = f"https://{value}"

    parsed = urlparse(value, scheme="https")
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc
    path = parsed.path

    if not netloc:
        parts = (parsed.path or "").split("/", 1)
        netloc = parts[0]
        path = ""
        if len(parts) == 2:
            path = "/" + parts[1]
    if not netloc:
        return None

    base = f"{scheme.lower()}://{netloc}"
    if path and path not in ("", "/"):
        base = f"{base}{path.rstrip('/')}"

    base = base.rstrip("/")
    parsed_final = urlparse(base, scheme="https")
    if (
        parsed_final.scheme not in {"http", "https"}
        or not parsed_final.netloc
        or "//" in parsed_final.netloc
        or parsed_final.netloc.lower().startswith(("http", "https"))
    ):
        return None
    return base


def _detect_ngrok_public_url() -> Optional[str]:
    global NGROK_PUBLIC_URL, NGROK_LAST_CHECK
    now = time.time()
    if NGROK_PUBLIC_URL and (now - NGROK_LAST_CHECK) < NGROK_CHECK_INTERVAL:
        return NGROK_PUBLIC_URL
    # Avoid hammering 4040; only retry every few seconds when unresolved
    if (now - NGROK_LAST_CHECK) < 5.0:
        return NGROK_PUBLIC_URL

    for endpoint in ("http://127.0.0.1:4040/api/tunnels", "http://localhost:4040/api/tunnels"):
        try:
            with urllib.request.urlopen(endpoint, timeout=0.5) as resp:
                data = json.load(resp)
        except Exception:
            continue

        tunnels = data.get("tunnels") or []
        candidates = []
        for t in tunnels:
            public_url = t.get("public_url")
            normalized = _normalize_base_url(public_url)
            if normalized:
                candidates.append(normalized)
        candidates.sort(key=lambda u: (0 if u.startswith("https://") else 1, len(u)))
        if candidates:
            NGROK_PUBLIC_URL = candidates[0]
            NGROK_LAST_CHECK = now
            return NGROK_PUBLIC_URL

    NGROK_LAST_CHECK = now
    return NGROK_PUBLIC_URL


def _public_base_url(request: Request) -> str:
    if CHECKIN_FORCED_BASE_URL:
        return CHECKIN_FORCED_BASE_URL
    normalized = _normalize_base_url(PUBLIC_BASE_URL)
    if normalized:
        return normalized
    detected = _detect_ngrok_public_url()
    if detected:
        return detected
    origin = _normalize_base_url(request.headers.get("origin"))
    if origin:
        return origin
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    host = host.split(",")[0].strip()
    if not host or host.lower() in {"http", "https"}:
        host = request.url.hostname or ""
        port = request.url.port
        if host:
            if port and port not in (80, 443):
                host = f"{host}:{port}"
    if not host:
        client_host = getattr(request.client, "host", None)
        if client_host:
            host = client_host
            port = getattr(request.client, "port", None)
            if port and port not in (80, 443):
                host = f"{host}:{port}"
        else:
            host = "localhost"
    if host and (host.endswith("ngrok-free.app") or host.endswith("ngrok-free.dev") or host.endswith("ngrok-free.io")):
        proto = "https"
    if RP_ID and RP_ID != "localhost" and RP_ID not in host:
        return f"https://{RP_ID}".rstrip("/")
    return f"{proto}://{host}".rstrip("/")


# =========================
# WebAuthn
# =========================
@app.get("/webauthn/rpinfo")
def webauthn_rpinfo():
    return {"rp_id": RP_ID}


@app.post("/webauthn/register/options")
async def webauthn_register_options(request: Request):
    body = await request.json()
    student_id = str(body.get("student_id") or "").strip()
    if not student_id:
        return JSONResponse({"detail": "student_id required"}, status_code=400)

    _require_checkin_network(request)

    server = _get_fido2_server(request)
    user = PublicKeyCredentialUserEntity(
        id=student_id.encode("utf-8"),
        name=student_id,
        display_name=student_id,
    )

    options, state = server.register_begin(
        user=user,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    public_key = options.get("publicKey", options)
    public_key["challenge"] = _b64u_if_bytes(public_key.get("challenge"))
    if "user" in public_key and isinstance(public_key["user"], dict):
        public_key["user"]["id"] = _b64u_if_bytes(public_key["user"].get("id"))

    if isinstance(public_key.get("excludeCredentials"), list):
        converted = []
        for cred in public_key["excludeCredentials"]:
            if isinstance(cred, dict):
                converted.append({**cred, "id": _b64u_if_bytes(cred.get("id"))})
        public_key["excludeCredentials"] = converted

    state_key = f"{student_id}|{request.client.host}"
    WEBAUTHN_STATE[state_key] = state

    return {"publicKey": public_key}


@app.post("/webauthn/register/complete")
async def webauthn_register_complete(request: Request):
    body = await request.json()
    student_id = str(body.get("student_id") or "").strip()
    if not student_id:
        return JSONResponse({"detail": "student_id required"}, status_code=400)

    state_key = f"{student_id}|{request.client.host}"
    state = WEBAUTHN_STATE.pop(state_key, None)
    if state is None:
        return JSONResponse({"detail": "no registration state"}, status_code=400)

    server = _get_fido2_server(request)
    attestation_response = {
        "id": body.get("id"),
        "rawId": body.get("rawId"),
        "type": body.get("type"),
        "response": body.get("response"),
        "clientExtensionResults": body.get("clientExtensionResults", {}),
    }

    auth_data = server.register_complete(state, attestation_response)
    cred = auth_data.credential_data
    cred_id_bytes = bytes(cred.credential_id)
    public_key_cbor = _cbor_encode(cred.public_key)
    sign_count = int(getattr(auth_data, "sign_count", 0) or 0)

    upsert_credential(student_id, cred_id_bytes, public_key_cbor, sign_count, transports=None)

    credential_id = _b64u_if_bytes(cred.credential_id)
    return {"ok": True, "credential_id": credential_id}


@app.post("/webauthn/auth/options")
async def webauthn_auth_options(request: Request, data: dict = Body(...)):
    student_id = str(data.get("student_id") or "").strip()
    if not student_id:
        raise HTTPException(status_code=400, detail="student_id required")

    _require_checkin_network(request)

    server = make_fido_server(request)
    creds = _load_credentials_for_user(student_id)
    if not creds:
        return JSONResponse({"detail": "등록된 기기가 없습니다. 먼저 기기 등록을 완료하세요."}, status_code=404)

    descriptors = []
    for cred in creds:
        transports = None
        if cred.get("transports"):
            transports = [t.strip() for t in cred["transports"].split(",") if t.strip()]
        cred_id = cred["credential_id"]
        if not isinstance(cred_id, (bytes, bytearray)):
            cred_id = bytes(cred_id)
        descriptors.append(
            PublicKeyCredentialDescriptor(
                type="public-key",
                id=cred_id,
                transports=transports,
            )
        )

    options, state = server.authenticate_begin(
        descriptors,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    public_key = options.get("publicKey", options)
    public_key["challenge"] = _b64u_if_bytes(public_key.get("challenge"))
    if isinstance(public_key.get("allowCredentials"), list):
        converted = []
        for cred in public_key["allowCredentials"]:
            if isinstance(cred, dict):
                converted.append({**cred, "id": _b64u_if_bytes(cred.get("id"))})
        public_key["allowCredentials"] = converted

    FORM_TOKENS[f"webauthn_auth_state:{request.url.hostname}:{student_id}"] = state
    return {"publicKey": public_key}


@app.post("/webauthn/auth/complete")
async def webauthn_auth_complete(request: Request, body: dict = Body(...)):
    student_id = str(body.get("student_id") or "").strip()
    credential_dict = body.get("credential")
    if credential_dict is None:
        credential_dict = {
            "id": body.get("id"),
            "rawId": body.get("rawId"),
            "type": body.get("type"),
            "response": body.get("response"),
            "clientExtensionResults": body.get("clientExtensionResults", {}),
        }

    response_dict = credential_dict.get("response") or {}
    if not student_id or not response_dict:
        raise HTTPException(status_code=400, detail="invalid payload")

    session_id = int(body.get("session_id") or 0)
    token_value = str(body.get("token") or "").strip()
    device_name = str(body.get("device_name") or "")
    if not session_id or not token_value:
        raise HTTPException(status_code=400, detail="session_id and token required")

    server = make_fido_server(request)

    try:
        from fido2.webauthn import AuthenticationResponse
        assertion_response = AuthenticationResponse.from_dict(credential_dict)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid credential payload") from exc

    raw_id_b64 = (
        credential_dict.get("rawId")
        or credential_dict.get("id")
        or body.get("rawId")
        or body.get("id")
    )
    credential_id_bytes = None
    if isinstance(raw_id_b64, str):
        try:
            credential_id_bytes = _b64u_decode(raw_id_b64)
        except Exception:
            credential_id_bytes = None

    state_key = f"webauthn_auth_state:{request.url.hostname}:{student_id}"
    state = FORM_TOKENS.pop(state_key, None)
    if state is None:
        raise HTTPException(status_code=400, detail="no auth state")

    creds = _load_credentials_for_user(student_id)
    if not creds:
        raise HTTPException(status_code=404, detail="credential not registered")

    registered = []
    target_entry = None
    for c in creds:
        stored_id = c["credential_id"]
        if isinstance(stored_id, memoryview):
            stored_id = stored_id.tobytes()
        elif not isinstance(stored_id, (bytes, bytearray)):
            stored_id = bytes(stored_id)

        try:
            public_key = _deserialize_public_key(c["public_key"])
        except ValueError:
            continue

        fido_cred = _StoredCredential(
            credential_id=stored_id,
            public_key=public_key,
            sign_count=c["sign_count"],
            transports=c.get("transports"),
        )
        registered.append(fido_cred)

        if credential_id_bytes is not None and stored_id == credential_id_bytes:
            target_entry = fido_cred

    if not registered:
        raise HTTPException(status_code=404, detail="credential not registered")

    if credential_id_bytes is None:
        target_entry = target_entry or registered[0]
        credential_id_bytes = target_entry["credential_id"]
    elif target_entry is None:
        raise HTTPException(status_code=404, detail="credential not registered")

    response = assertion_response["response"] if isinstance(assertion_response, Mapping) else credential_dict.get("response", {})
    if not response:
        raise HTTPException(status_code=400, detail="invalid credential payload")

    client_data_b64 = response.get("clientDataJSON")
    auth_data_b64 = response.get("authenticatorData")
    signature_b64 = response.get("signature")
    user_handle_b64 = response.get("userHandle")
    if not (client_data_b64 and auth_data_b64 and signature_b64):
        raise HTTPException(status_code=400, detail="invalid credential payload")

    try:
        client_data_bytes = _b64u_decode(client_data_b64)
        auth_data_bytes = _b64u_decode(auth_data_b64)
        signature_bytes = _b64u_decode(signature_b64)
        user_handle_bytes = _b64u_decode(user_handle_b64) if user_handle_b64 else None
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid credential payload") from exc

    try:
        client_data_obj = CollectedClientData(client_data_bytes)
        auth_data_obj = AuthenticatorData(auth_data_bytes)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid credential payload") from exc

    try:
        result = server.authenticate_complete(
            state,
            registered,
            credential_id_bytes,
            client_data_obj,
            auth_data_obj,
            signature_bytes,
            user_handle=user_handle_bytes,
        )
    except TypeError:
        result = server.authenticate_complete(
            state,
            registered,
            credential_id_bytes,
            client_data_obj,
            auth_data_obj,
            signature_bytes,
        )

    new_sign_count = getattr(result, "new_sign_count", getattr(result, "sign_count", None))
    if new_sign_count is None:
        raise HTTPException(status_code=500, detail="credential verification failed")
    cred_id = getattr(result, "credential_id", credential_id_bytes)

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE webauthn_credentials SET sign_count=? WHERE credential_id=?",
        (new_sign_count, cred_id),
    )
    conn.commit()
    conn.close()

    attendance_info = _record_attendance(session_id, student_id, token_value, device_name, request)

    return {"ok": True, "checked_in": True, "sign_count": new_sign_count, **attendance_info}

# =========================
# QR(JWT) issue / verification
# =========================
def _verify_qr_token(t: str):
    """
    Validate JWT and ensure it matches the most recent nonce.
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

    nonce_map = QR_NONCES.get(sid)
    if not nonce_map:
        raise HTTPException(status_code=410, detail="QR rotated")

    now = int(time.time())
    stale = [n for n, exp in nonce_map.items() if exp < now]
    for old in stale:
        nonce_map.pop(old, None)
    if not nonce_map:
        QR_NONCES.pop(sid, None)
    if nonce not in nonce_map:
        raise HTTPException(status_code=410, detail="QR rotated")

    return sid, nonce, data


def _store_qr_token(session_id: int, token: str, generated_at: str, valid_until: str) -> None:
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO qr_tokens(session_id, token, generated_at, valid_until) VALUES(?,?,?,?)",
            (session_id, token, generated_at, valid_until),
        )
        conn.commit()
    finally:
        conn.close()


def _new_qr_token(session_id: int, ttl: int = QR_PERIOD_SECONDS) -> tuple[str, int, str, str, int]:
    """
    Issue a new QR JWT, cache it in memory, and persist metadata.
    Returns (token, exp_epoch, generated_at_iso, valid_until_iso, display_ttl_seconds).
    """
    nonce = secrets.token_urlsafe(8)
    display_ttl = max(5, ttl)
    ttl_seconds = display_ttl + max(0, QR_TOKEN_GRACE_SECONDS)
    now_epoch = int(time.time())
    exp_epoch = now_epoch + ttl_seconds
    now_local = datetime.now()
    generated_at = now_local.strftime("%Y-%m-%d %H:%M:%S")
    valid_until = (now_local + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%d %H:%M:%S")
    payload = {"sid": session_id, "nonce": nonce, "exp": exp_epoch, "ga": generated_at}
    token = jwt.encode(payload, QR_SECRET, algorithm=JWT_ALG)
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    nonce_map = QR_NONCES.setdefault(session_id, {})
    now_epoch = int(time.time())
    expired_nonces = [n for n, exp in nonce_map.items() if exp < now_epoch]
    for n in expired_nonces:
        nonce_map.pop(n, None)
    nonce_map[nonce] = exp_epoch
    LATEST_QR_TOKEN[session_id] = token
    _store_qr_token(session_id, token, generated_at, valid_until)
    return token, exp_epoch, generated_at, valid_until, display_ttl


# =========================
# Admin: QR issue / rotation / image
# =========================
@app.post("/api/qr/issue")
def issue_qr(session_id: int, ttl: int = QR_PERIOD_SECONDS):
    token, exp_epoch, issued_at, valid_until, display_ttl = _new_qr_token(session_id, ttl)
    return {
        "token": token,
        "exp": exp_epoch,
        "issued_at": issued_at,
        "valid_until": valid_until,
        "refresh_after": display_ttl,
    }


@app.post("/api/qr/stop")
def stop_qr(session_id: int = Query(...)):
    QR_NONCES.pop(session_id, None)
    LATEST_QR_TOKEN.pop(session_id, None)
    return {"stopped": True}


@app.get("/api/qr/image")
async def api_qr_image(request: Request, session_id: Optional[int] = None):
    sid = session_id or current_session_id()
    if not sid:
        raise HTTPException(status_code=404, detail="no active session")

    token = LATEST_QR_TOKEN.get(sid)
    if token:
        try:
            payload = jwt.decode(token, QR_SECRET, algorithms=[JWT_ALG], options={"verify_exp": False})
            if int(payload.get("exp", 0)) <= int(time.time()):
                token, _, _, _, _ = _new_qr_token(sid, QR_PERIOD_SECONDS)
        except Exception:
            token, _, _, _, _ = _new_qr_token(sid, QR_PERIOD_SECONDS)
    else:
        token, _, _, _, _ = _new_qr_token(sid, QR_PERIOD_SECONDS)

    base = _public_base_url(request)
    url = f"{base}/checkin?t={token}"

    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/api/qr/current")
def api_qr_current(request: Request, session_id: Optional[int] = None):
    sid = session_id or current_session_id()
    if not sid:
        conn = db()
        cur = conn.cursor()
        try:
            start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            end = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
            cur.execute(
                "INSERT INTO sessions(class_id, start_time, end_time) VALUES(?,?,?)",
                ("CLS101", start, end),
            )
            conn.commit()
            sid = cur.lastrowid
        finally:
            conn.close()

    token, exp_epoch, generated_at, valid_until, display_ttl = _new_qr_token(sid, QR_PERIOD_SECONDS)
    base = _public_base_url(request)
    qr_path = f"/checkin?t={token}"
    qrboard_path = f"/qrboard?session_id={sid}"

    return {
        "session_id": sid,
        "token": token,
        "generated_at": generated_at,
        "valid_until": valid_until,
        "exp": exp_epoch,
        "refresh_after": display_ttl,
        "grace_seconds": QR_TOKEN_GRACE_SECONDS,
        "qr_url": f"{base}{qr_path}",
        "qrboard_url": f"{base}{qrboard_path}",
        "qr_path": qr_path,
        "qrboard_path": qrboard_path,
        "public_base_url": base,
    }
@app.get("/qrboard", response_class=HTMLResponse)
def qrboard_page(session_id: Optional[int] = None):
    html_path = os.path.join(os.path.dirname(__file__), "../frontend/qrboard.html")
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
    except Exception:
        raise HTTPException(status_code=500, detail="qrboard template missing")
    return HTMLResponse(html)



# =========================
# 라우트: 체크인 페이지(토큰 필요)
# =========================
EXPIRED_HTML = """
<!doctype html><meta charset="utf-8">
<style>body{font-family:system-ui;padding:40px;text-align:center}</style>
<h2>QR 유효시간이 지났습니다</h2>
<p>새 QR 코드로 다시 접속해주세요.</p>
"""

FORBIDDEN_NETWORK_HTML = """
<!doctype html><meta charset="utf-8">
<style>body{font-family:system-ui;padding:40px;text-align:center}</style>
<h2>허용된 네트워크에서만 접속 가능합니다</h2>
<p>지정된 Wi-Fi/핫스팟에 연결한 뒤 QR 코드를 다시 스캔해주세요.</p>
"""

@app.get("/checkin", response_class=HTMLResponse)
def checkin_page(request: Request, t: str = Query(...)):
    if not _is_request_allowed_for_checkin(request):
        return HTMLResponse(FORBIDDEN_NETWORK_HTML, status_code=403)

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
    """현재 세션의 의심 행위 점수를 CSV로 내보낸다."""
    results, _ = _analyze_session(session_id)

    filtered = []
    for item in results:
        score = int(item.get("score", 0))
        if min_score > 0 and score > min_score:
            continue
        flags_str = "|".join(item.get("flags") or [])
        filtered.append([item.get("student_id"), score, flags_str])

    data = _csv_bytes(rows=filtered, header=["student_id", "score", "flags"], encoding="cp949")
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


def valid_token(session_id: int, token: str):
    if not session_id or not token:
        return None
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT generated_at, valid_until FROM qr_tokens WHERE session_id=? AND token=? ORDER BY id DESC LIMIT 1", (session_id, token))
        row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return None
    generated_at = row["generated_at"] or ""
    valid_until = row["valid_until"] or ""
    if valid_until:
        try:
            expiry = datetime.strptime(valid_until, "%Y-%m-%d %H:%M:%S")
        except Exception:
            try:
                expiry = datetime.fromisoformat(valid_until)
            except Exception:
                expiry = None
        if expiry and datetime.now() > expiry:
            return None
    return {"generated_at": generated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

def _record_attendance(session_id: int, student_id: str, token: str, device_name: str, request: Request):
    if not session_id or not student_id or not token:
        raise HTTPException(status_code=400, detail="invalid payload")

    _require_checkin_network(request)

    now_epoch = int(time.time())
    ft = FORM_TOKENS.get(token)
    if ft:
        if now_epoch > ft.get("exp", 0):
            FORM_TOKENS.pop(token, None)
            raise HTTPException(status_code=400, detail="form token expired")
        if int(ft.get("sid", 0)) != session_id:
            raise HTTPException(status_code=400, detail="session mismatch")
        FORM_TOKENS.pop(token, None)
        qr_generated_at = ft.get("issued_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    else:
        vt = valid_token(session_id, token)
        if not vt:
            raise HTTPException(status_code=400, detail="invalid or expired token")
        qr_generated_at = vt.get("generated_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ip = client_ip(request)
    ua = request.headers.get("user-agent", "")
    device = (device_name or ua[:64]).strip()

    conn = db()
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        "INSERT INTO attendance_logs(session_id, student_id, checked_at, ip, user_agent, token, qr_generated_at, anomaly_flags, device_name) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (session_id, student_id, now, ip, ua, token, qr_generated_at, "", device)
    )
    conn.commit()
    conn.close()
    snapshot_session_csvs(session_id)

    return {
        "checked_at": now,
        "qr_generated_at": qr_generated_at,
        "device_name": device,
        "ip": ip,
    }




@app.post("/api/attendance/check-in")
async def api_check_in(data: dict, request: Request):
    raise HTTPException(status_code=403, detail="biometric authentication required")



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
async def api_sessions(limit: int = 100):
    limit = max(1, min(int(limit), 500))
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id, class_id, start_time, end_time FROM sessions ORDER BY start_time DESC LIMIT ?", (limit,))
    rows = cur.fetchall(); conn.close()
    out = []
    for r in rows:
        out.append({"id": r["id"], "class_id": r["class_id"], "start_time": r["start_time"], "end_time": r["end_time"]})
    return {"sessions": out}

# --- 세션별 출석/공결 조회 API (대시보드가 사용) -----------------------------

@app.delete("/api/session/{session_id}")
async def api_session_delete(session_id: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT start_time FROM sessions WHERE id=?", (session_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="session not found")

    for table in ("attendance_logs", "qr_tokens", "excused_attendance"):
        try:
            cur.execute(f"DELETE FROM {table} WHERE session_id=?", (session_id,))
        except Exception:
            continue
    conn.commit()

    cur.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    conn.commit()
    conn.close()

    QR_NONCES.pop(session_id, None)
    LATEST_QR_TOKEN.pop(session_id, None)

    session_date = row["start_time"][:10] if row["start_time"] else None
    if session_date:
        export_dir = _session_export_dir(session_id, session_date)
        if os.path.isdir(export_dir):
            try:
                shutil.rmtree(export_dir)
            except Exception:
                pass

    return {"deleted": True, "session_id": session_id}


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
        "SELECT id, student_id, checked_at, ip, device_name, anomaly_flags "
        "FROM attendance_logs WHERE session_id=? ORDER BY id ASC",
        (session_id,)
    )
    rows = cur.fetchall()
    conn.close()

    logs = [
        {
            "log_id": r["id"],
            "student_id": r["student_id"],
            "checked_at": r["checked_at"],
            "ip": r["ip"],
            "device_name": r["device_name"],
            "note": r["anomaly_flags"] or "",
        }
        for r in rows
    ]
    return {"session_id": session_id, "logs": logs}


@app.post("/api/attendance/manual")
async def api_attendance_manual(data: dict = Body(...), request: Request = None):
    session_id = int(data.get("session_id") or 0)
    student_id = str(data.get("student_id") or "").strip()
    note = str(data.get("note") or "임의 출석").strip()
    if not session_id or not student_id:
        raise HTTPException(status_code=400, detail="session_id and student_id required")

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT start_time FROM sessions WHERE id=?", (session_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="session not found")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = client_ip(request) if request else ""
    ua = request.headers.get("user-agent", "") if request else ""
    anomaly = note or "임의 출석"

    cur.execute(
        "SELECT id, anomaly_flags FROM attendance_logs WHERE session_id=? AND student_id=? ORDER BY id ASC LIMIT 1",
        (session_id, student_id),
    )
    existing = cur.fetchone()
    if existing:
        flags = existing["anomaly_flags"] or ""
        parts = {f.strip() for f in flags.split(";") if f.strip()}
        parts.add(anomaly)
        combined = "; ".join(sorted(parts))
        cur.execute(
            "UPDATE attendance_logs SET checked_at=?, anomaly_flags=?, device_name=?, ip=?, user_agent=? WHERE id=?",
            (now, combined, "Manual Entry", ip, ua, existing["id"]),
        )
    else:
        cur.execute(
            """
            INSERT INTO attendance_logs(session_id, student_id, checked_at, ip, user_agent, token, qr_generated_at, anomaly_flags, device_name)
            VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (session_id, student_id, now, ip, ua, None, now, anomaly, "Manual Entry"),
        )

    conn.commit()
    conn.close()
    snapshot_session_csvs(session_id)
    return {"ok": True, "session_id": session_id, "student_id": student_id, "note": anomaly, "checked_at": now}

@app.delete("/api/attendance/log/{log_id}")
async def api_attendance_delete(log_id: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT session_id FROM attendance_logs WHERE id=?", (log_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="attendance log not found")
    session_id = row["session_id"]
    cur.execute("DELETE FROM attendance_logs WHERE id=?", (log_id,))
    conn.commit()
    conn.close()
    snapshot_session_csvs(session_id)
    return {"deleted": True, "session_id": session_id, "log_id": log_id}




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
        "SELECT id, student_id, excuse_type, evidence_ok, notes, mail_time "
        "FROM email_excuses WHERE session_date=? ORDER BY id ASC",
        (session_date,)
    )
    rows = cur.fetchall()
    conn.close()

    excuses = []
    for r in rows:
        mail_time = r["mail_time"] if "mail_time" in r.keys() else ""
        excuses.append(
            {
                "id": r["id"],
                "student_id": r["student_id"],
                "excuse_type": r["excuse_type"],
                "evidence_ok": bool(r["evidence_ok"]),
                "notes": r["notes"] or "",
                "mail_time": mail_time or "",
                "session_date": session_date,
            }
        )
    return {"session_id": session_id, "session_date": session_date, "excuses": excuses}


@app.get("/api/excuses/recent")
async def api_excuses_recent(days: int = Query(30, ge=1, le=365), limit: int = Query(50, ge=1, le=500)):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    conn = db(); cur = conn.cursor()
    cur.execute(
        """
        SELECT id, session_date, student_id, excuse_type, evidence_ok, notes, mail_time
        FROM email_excuses
        WHERE session_date >= ?
        ORDER BY session_date DESC, id DESC
        LIMIT ?
        """,
        (cutoff, limit),
    )
    rows = cur.fetchall()
    conn.close()

    payload = []
    for r in rows:
        mail_time = r["mail_time"] if "mail_time" in r.keys() else ""
        payload.append(
            {
                "id": r["id"],
                "session_date": r["session_date"],
                "student_id": r["student_id"],
                "excuse_type": r["excuse_type"],
                "evidence_ok": bool(r["evidence_ok"]),
                "notes": r["notes"] or "",
                "mail_time": mail_time or "",
            }
        )

    return {"rows": payload, "days": days, "limit": limit}


@app.post("/api/excuses/gmail/ingest")
async def api_excuses_gmail_ingest(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    query: str = Query(""),
):
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    override_date = str(payload.get("override_date", "")).strip() or None

    try:
        from . import gmail_ingest as gmail_module
    except ImportError:
        import backend.gmail_ingest as gmail_module  # type: ignore

    try:
        result = await asyncio.to_thread(
            gmail_module.run,
            query or "",
            days,
            override_date,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"gmail ingest failed: {exc}") from exc

    (
        found,
        upserted,
        sid_missing,
        invalid_sid,
        skipped,
        failed,
        gemini_active,
        touched_dates,
    ) = result

    refreshed_sessions = _refresh_sessions_for_dates(touched_dates)

    return {
        "found": found,
        "upserted": upserted,
        "sid_missing": sid_missing,
        "invalid_sid": invalid_sid,
        "skipped": skipped,
        "failed": failed,
        "gemini_active": bool(gemini_active),
        "touched_dates": touched_dates,
        "refreshed_sessions": sorted(refreshed_sessions),
    }


@app.post("/api/excuses/manual")
async def api_excuses_manual(data: dict = Body(...)):
    student_id = str(data.get("student_id") or "").strip()
    if not student_id:
        raise HTTPException(status_code=400, detail="student_id required")

    session_id = data.get("session_id")
    session_date = str(data.get("session_date") or "").strip()
    resolved_session_id: Optional[int] = None

    if session_id:
        resolved_session_id = int(session_id)
        conn = db(); cur = conn.cursor()
        cur.execute("SELECT start_time FROM sessions WHERE id=?", (resolved_session_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail="session not found")
        session_date = str(row["start_time"])[:10]
    elif session_date:
        session_date = session_date[:10]
    else:
        raise HTTPException(status_code=400, detail="session_id or session_date required")

    excuse_type = str(data.get("excuse_type") or "공결").strip()
    if excuse_type not in {"공결", "병결"}:
        raise HTTPException(status_code=400, detail="excuse_type must be 공결 or 병결")

    evidence_ok = bool(data.get("evidence_ok", False))
    notes = _sanitize_notes(str(data.get("notes") or "").strip())
    now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = db(); cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id FROM email_excuses WHERE student_id=? AND session_date=?",
            (student_id, session_date),
        )
        row = cur.fetchone()
        if row:
            cur.execute(
                """
                UPDATE email_excuses
                   SET excuse_type=?, evidence_ok=?, notes=?, msg_id=NULL,
                       ai_label=?, ai_confidence=?, ai_reason=?, mail_time=?
                 WHERE id=?
                """,
                (
                    excuse_type,
                    int(evidence_ok),
                    notes,
                    excuse_type,
                    1.0,
                    notes,
                    now_ts,
                    row["id"],
                ),
            )
            excuse_id = row["id"]
        else:
            cur.execute(
                """
                INSERT INTO email_excuses(
                    student_id, session_date, excuse_type, evidence_ok, notes,
                    msg_id, ai_label, ai_confidence, ai_reason, mail_time
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    student_id,
                    session_date,
                    excuse_type,
                    int(evidence_ok),
                    notes,
                    None,
                    excuse_type,
                    1.0,
                    notes,
                    now_ts,
                ),
            )
            excuse_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    refreshed_sessions = _refresh_sessions_for_dates([session_date])
    return {
        "ok": True,
        "excuse_id": excuse_id,
        "student_id": student_id,
        "session_date": session_date,
        "session_id": resolved_session_id,
        "excuse_type": excuse_type,
        "evidence_ok": evidence_ok,
        "notes": notes,
        "refreshed_sessions": refreshed_sessions,
    }


@app.delete("/api/excuses/{excuse_id}")
async def api_excuses_delete(excuse_id: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT session_date FROM email_excuses WHERE id=?", (excuse_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="excuse not found")
    session_date = row["session_date"]
    cur.execute("DELETE FROM email_excuses WHERE id=?", (excuse_id,))
    conn.commit()
    conn.close()

    refreshed_sessions = _refresh_sessions_for_dates([session_date])
    return {
        "deleted": True,
        "excuse_id": excuse_id,
        "session_date": session_date,
        "refreshed_sessions": refreshed_sessions,
    }

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
    w.writerow(["student_id","checked_at","status","ip","device_name","token","qr_generated_at","note"])
    for r in rows:
        flags = (r["anomaly_flags"] or "").strip()
        status = "O"
        if flags:
            status = f"O ({flags})"
        w.writerow([
            r["student_id"],
            r["checked_at"],
            status,
            r["ip"] or "",
            r["device_name"] or "",
            r["token"] or "",
            r["qr_generated_at"] or "",
            flags
        ])
    data = buf.getvalue()
    return Response(content=data, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="attendance_{session_id}.csv"'})

@app.get("/api/export/excuses/recent.csv")
async def api_export_excuses_recent(days: int = 14, enc: str = "cp949"):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT student_id, session_date, excuse_type, evidence_ok, notes, mail_time
        FROM email_excuses
        WHERE session_date >= ?
        ORDER BY session_date ASC, id ASC
    """, (cutoff,))
    rows = cur.fetchall(); conn.close()
    data = _csv_bytes(
        rows=[[r["session_date"], r["student_id"], r["excuse_type"], int(r["evidence_ok"] or 0), _sanitize_notes(r["notes"]), r["mail_time"] if "mail_time" in r.keys() else ""] for r in rows],
        header=["session_date","student_id","excuse_type","evidence_ok","notes","mail_time"],
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
        SELECT student_id, excuse_type, evidence_ok, notes, mail_time
        FROM email_excuses
        WHERE session_date=?
        ORDER BY id ASC
    """, (d,))
    rows = cur.fetchall(); conn.close()
    data = _csv_bytes(
        rows=[[d, r["student_id"], r["excuse_type"], int(r["evidence_ok"] or 0), _sanitize_notes(r["notes"]), r["mail_time"] if "mail_time" in r.keys() else ""] for r in rows],
        header=["session_date","student_id","excuse_type","evidence_ok","notes","mail_time"],
        encoding=enc
    )
    return Response(content=data, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="excuses_{session_id}.csv"'})

# -------------------------
# 전체 출석 집계 CSV
# -------------------------
@app.get("/api/export/attendance/overall.csv")
def api_export_attendance_overall():
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id, class_id, start_time, end_time FROM sessions ORDER BY start_time ASC")
    sessions = [dict(row) for row in cur.fetchall()]
    cur.execute("SELECT session_id, student_id, checked_at, qr_generated_at, ip, device_name, anomaly_flags FROM attendance_logs")
    log_rows = [dict(row) for row in cur.fetchall()]
    cur.execute("SELECT session_date, student_id, excuse_type, evidence_ok FROM email_excuses")
    excuses = [dict(row) for row in cur.fetchall()]
    conn.close()

    if not sessions:
        data = _csv_bytes(rows=[], header=["student_id", "total_present"], encoding="cp949")
        return Response(content=data, media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="attendance_overall.csv"'})

    attendance_map: dict[str, dict[int, list[dict]]] = {}
    rows_by_session: dict[int, list[dict]] = {}
    students: set[str] = set()

    for row in log_rows:
        sid = str(row.get("student_id") or "").strip()
        sess_id = int(row.get("session_id") or 0)
        if not sid or not sess_id:
            continue
        students.add(sid)
        attendance_map.setdefault(sid, {}).setdefault(sess_id, []).append(row)
        rows_by_session.setdefault(sess_id, []).append(row)

    valid_excuse_types = {"공결", "병결"}
    excuse_map: dict[tuple[str, str], dict] = {}
    for exc in excuses:
        etype = (exc.get("excuse_type") or "").strip()
        if etype not in valid_excuse_types:
            continue
        sid = str(exc.get("student_id") or "").strip()
        session_date = (exc.get("session_date") or "").strip()
        if not sid or not session_date:
            continue
        excuse_map[(session_date, sid)] = exc
        students.add(sid)

    session_anomaly_notes: dict[tuple[int, str], str] = {}
    for sess in sessions:
        sess_id = int(sess.get("id") or 0)
        sess_rows = rows_by_session.get(sess_id)
        if not sess_rows:
            continue
        s_start = _parse_local_dt(sess.get("start_time"))
        s_end = _parse_local_dt(sess.get("end_time"))
        if not s_start:
            continue
        if not s_end:
            s_end = s_start + timedelta(hours=3)
        _, _, reason_lookup = _compute_anomalies(sess_id, s_start, s_end, sess_rows)
        for student, reasons in reason_lookup.items():
            if reasons:
                session_anomaly_notes[(sess_id, student)] = "; ".join(reasons)

    header = ["student_id"] + [f"{sess['start_time']} (#{sess['id']})" for sess in sessions] + ["total_present"]
    rows_out: list[list[str]] = []

    for student in sorted(students):
        total = 0
        cells = [student]
        per_session = attendance_map.get(student, {})
        for sess in sessions:
            sess_id = int(sess.get("id") or 0)
            entries = per_session.get(sess_id, [])
            if entries:
                total += 1
                note_values = [entry.get("anomaly_flags") for entry in entries]
                suspect_note = session_anomaly_notes.get((sess_id, student))
                note_text = _merge_notes(*note_values, suspect_note)
                cell = "O" if not note_text else f"O ({note_text})"
            else:
                sess_date = str(sess.get("start_time") or "")[:10]
                exc = excuse_map.get((sess_date, student))
                if exc:
                    etype = (exc.get("excuse_type") or "공결").strip() or "공결"
                    if exc.get("evidence_ok"):
                        cell = f"{etype} (증빙O)"
                    else:
                        cell = etype
                    total += 1
                else:
                    cell = "X"
            cells.append(cell)
        cells.append(str(total))
        rows_out.append(cells)

    data = _csv_bytes(rows=rows_out, header=header, encoding="cp949")
    return Response(content=data, media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="attendance_overall.csv"'})
def _compute_anomalies(session_id: int, session_start: Optional[datetime], session_end: Optional[datetime], rows: list[Mapping]) -> tuple[list[dict], list[dict], dict[str, list[str]]]:
    ip_to_students: dict[str, set[str]] = {}
    device_to_students: dict[str, set[str]] = {}
    seen: set[tuple[str, str, str]] = set()
    prev_by_student: dict[str, datetime] = {}
    student_counts: dict[str, int] = {}

    fast_flags: set[str] = set()
    dup_flags: set[str] = set()
    shared_ip_flags: set[str] = set()
    shared_device_flags: set[str] = set()
    out_of_window: set[str] = set()
    burst_flags: set[str] = set()

    for raw in rows:
        row = dict(raw)
        sid = str(row.get("student_id") or "").strip()
        if not sid:
            continue

        student_counts[sid] = student_counts.get(sid, 0) + 1

        ip = (row.get("ip") or "").strip()
        if ip:
            ip_to_students.setdefault(ip, set()).add(sid)

        device_name = (row.get("device_name") or "").strip()
        if device_name:
            device_to_students.setdefault(device_name, set()).add(sid)

        ca = _parse_local_dt(row.get("checked_at"))
        ga = _parse_local_dt(row.get("qr_generated_at"))
        if ca and ga and (ca - ga).total_seconds() < 2:
            fast_flags.add(sid)

        key = (sid, ip, str(row.get("checked_at") or ""))
        if key in seen:
            dup_flags.add(sid)
        seen.add(key)

        if ca and session_start and session_end:
            if ca < session_start or ca > session_end:
                out_of_window.add(sid)

        if ca:
            prev = prev_by_student.get(sid)
            if prev and (ca - prev).total_seconds() <= 5:
                burst_flags.add(sid)
            prev_by_student[sid] = ca

    for ip, sset in ip_to_students.items():
        if len(sset) >= 3:
            shared_ip_flags.update(sset)

    for device_name, sset in device_to_students.items():
        if len(sset) >= 2:
            shared_device_flags.update(sset)

    reasons_map: dict[str, set[str]] = {}

    def add_reason(sid: str, msg: str) -> None:
        if not msg:
            return
        reasons_map.setdefault(sid, set()).add(msg)

    for sid in fast_flags:
        add_reason(sid, "QR 생성 후 2초 내 접속")
    for sid in dup_flags:
        add_reason(sid, "중복 로그")
    for sid in shared_ip_flags:
        add_reason(sid, "동일 IP 다수 사용")
    for sid in shared_device_flags:
        add_reason(sid, "동일 기기 다수 사용")
    for sid in out_of_window:
        add_reason(sid, "세션 시간 외 접속")
    for sid in burst_flags:
        add_reason(sid, "5초 내 반복 접속")

    scores: dict[str, int] = {}
    for sid, count in student_counts.items():
        score = 100
        if sid in fast_flags:
            score -= 25
        if sid in dup_flags:
            score -= 20
        if sid in shared_ip_flags:
            score -= 40
        if count >= 3:
            score -= 10
        if sid in out_of_window:
            score -= 15
        if sid in burst_flags:
            score -= 10
        if sid in shared_device_flags:
            score -= 50
        if score < 0:
            score = 0
        scores[sid] = score

    results = []
    for sid in sorted(scores.keys(), key=lambda x: (scores[x], str(x))):
        flags: list[str] = []
        if sid in fast_flags:
            flags.append("fast")
        if sid in dup_flags:
            flags.append("dup")
        if sid in shared_ip_flags:
            flags.append("shared_ip")
        if sid in shared_device_flags:
            flags.append("shared_device")
        if sid in out_of_window:
            flags.append("out_of_window")
        if sid in burst_flags:
            flags.append("burst")
        results.append({"student_id": sid, "score": scores[sid], "flags": flags})

    suspects = [
        {"student_id": sid, "reasons": sorted(reasons)}
        for sid, reasons in reasons_map.items()
    ]
    suspects.sort(key=lambda item: (-len(item["reasons"]), str(item["student_id"])))

    reason_lookup = {sid: sorted(reasons) for sid, reasons in reasons_map.items()}
    return results, suspects, reason_lookup


def _analyze_session(session_id: int) -> tuple[list[dict], list[dict]]:
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT start_time, end_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        raise HTTPException(status_code=404, detail="no session")
    s_start = _parse_local_dt(srow["start_time"])
    s_end = _parse_local_dt(srow["end_time"])
    if s_start is None:
        conn.close()
        raise HTTPException(status_code=500, detail="session start time missing")
    if s_end is None:
        s_end = s_start + timedelta(hours=3)

    cur.execute("SELECT student_id, checked_at, ip, qr_generated_at, device_name FROM attendance_logs WHERE session_id=? ORDER BY id ASC", (session_id,))
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()

    results, suspects, _ = _compute_anomalies(session_id, s_start, s_end, rows)
    return results, suspects
@app.get("/api/anomaly/session/{session_id}")
async def api_anomaly(session_id: int):
    results, suspects = _analyze_session(session_id)
    return {"session_id": session_id, "results": results, "suspects": suspects}

@app.get("/api/anomaly/session/{session_id}/suspects")
async def api_anomaly_suspects(session_id: int):
    _, suspects = _analyze_session(session_id)
    return {"session_id": session_id, "suspects": suspects}

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
    cur.execute("SELECT start_time, end_time FROM sessions WHERE id=?", (session_id,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        return
    start_raw = srow["start_time"]
    session_date = start_raw[:10]
    outdir = _session_export_dir(session_id, session_date)

    s_start = _parse_local_dt(start_raw)
    s_end = _parse_local_dt(srow["end_time"]) if "end_time" in srow.keys() else None
    if s_start and not s_end:
        s_end = s_start + timedelta(hours=3)

    # 출석 로그 스냅샷
    cur.execute("""
        SELECT student_id, checked_at, ip, device_name, token, qr_generated_at, anomaly_flags
        FROM attendance_logs
        WHERE session_id=?
        ORDER BY id ASC
    """, (session_id,))
    att_rows_raw = [dict(row) for row in cur.fetchall()]

    reason_lookup: dict[str, list[str]] = {}
    if att_rows_raw and s_start:
        _, _, reason_lookup = _compute_anomalies(session_id, s_start, s_end or (s_start + timedelta(hours=3)), att_rows_raw)

    attendance_rows = []
    for row in att_rows_raw:
        student_id = row.get("student_id")
        suspect_notes = "; ".join(reason_lookup.get(student_id, [])) if student_id else ""
        combined_flags = _merge_notes(row.get("anomaly_flags"), suspect_notes)
        attendance_rows.append([
            student_id,
            row.get("checked_at"),
            row.get("ip") or "",
            row.get("device_name") or "",
            row.get("token") or "",
            row.get("qr_generated_at") or "",
            combined_flags,
        ])

    _write_csv_utf8bom(
        ["student_id","checked_at","ip","device_name","token","qr_generated_at","anomaly_flags"],
        attendance_rows,
        os.path.join(outdir, "attendance.csv")
    )

    # 공결 스냅샷(세션 날짜 기준)
    cur.execute("""
        SELECT student_id, excuse_type, evidence_ok, notes, mail_time
        FROM email_excuses
        WHERE session_date=?
        ORDER BY id ASC
    """, (session_date,))
    exc_rows = cur.fetchall()
    _write_csv_utf8bom(
        ["session_date","student_id","excuse_type","evidence_ok","notes","mail_time"],
        [[session_date, r["student_id"], r["excuse_type"], int(r["evidence_ok"] or 0), _sanitize_notes(r["notes"]), r["mail_time"] if "mail_time" in r.keys() else ""] for r in exc_rows],
        os.path.join(outdir, "excuses.csv")
    )

    conn.close()

# -------------------------
# 메인
# -------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

@app.get("/api/anomaly/current")
async def api_anomaly_current():
    sid = current_session_id()
    if not sid:
        raise HTTPException(status_code=404, detail="no active session")
    results, suspects = _analyze_session(sid)
    return {"session_id": sid, "results": results, "suspects": suspects}
    _require_checkin_network(request)

    _require_checkin_network(request)
