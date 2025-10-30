# -*- coding: utf-8 -*-
import os, sqlite3, base64, re, datetime, argparse, json, html, csv
from pathlib import Path
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from email.header import decode_header, make_header
from email.utils import getaddresses

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
BASE = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE, 'attendai.db')
CRED_FILE = os.path.join(BASE, 'credentials.json')
TOKEN_FILE = os.path.join(BASE, 'gmail_token.json')
ATTACH_DIR = os.path.join(BASE, 'attachments')

STUDENT_ID_REGEX = re.compile(r'\b(20\d{2})11(\d{3})\b')  # YYYY11XXX, 총 9자리

# 전부 Gemini로 강제
GEMINI_ON = True
GEMINI_MODEL_ENV = (os.getenv("GEMINI_MODEL") or "").strip()
GEMINI_MAX_CALLS = 1_000_000
GEMINI_ATTACH = os.getenv("GEMINI_ATTACH", "0") == "1"

ATTENDANCE_KEYWORDS = [
    "출석", "결석", "공결", "병결", "지각", "불참", "사유서", "출석인정", "출석 확인",
    "출장", "휴강", "대체수업", "보강", "우천", "질병", "입원", "가족상",
    "attendance", "absent", "absence", "excuse", "excused", "leave of absence",
    "tardy", "late arrival", "makeup class", "sick note", "medical certificate", "doctor's note"
]
ATTENDANCE_KEYWORDS_LOWER = [k.lower() for k in ATTENDANCE_KEYWORDS]


def _contains_attendance_keyword(*parts):
    haystack = " ".join(p for p in parts if p).lower()
    return any(k in haystack for k in ATTENDANCE_KEYWORDS_LOWER)


# =========================
# 유틸들
# =========================
def get_subject(full):
    headers = full.get('payload', {}).get('headers', [])
    for h in headers:
        if h.get('name','').lower() == 'subject':
            return str(make_header(decode_header(h.get('value',''))))
    return ''

def get_header_values(full, names):
    headers = full.get('payload', {}).get('headers', [])
    low = {h.get('name','').lower(): h.get('value','') for h in headers}
    return [low[n.lower()] for n in names if low.get(n.lower())]

def extract_addresses_and_names(full):
    vals = get_header_values(full, ['From','Sender','Reply-To','To','Cc','Bcc'])
    pairs = getaddresses(vals)
    emails = [a for _, a in pairs if a]
    names = [n for n, _ in pairs if n]
    return emails, names

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def lookup_student_id_by_email(addr):
    if not addr: return None
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id FROM students WHERE lower(email)=lower(?)", (addr.strip(),))
    row = cur.fetchone(); conn.close()
    return row["id"] if row else None

def upsert(student_id, session_date, excuse_type, evidence_ok, notes,
           msg_id=None, ai_label=None, ai_confidence=None, ai_reason=None):
    conn = db(); cur = conn.cursor()

    # 1) msg_id 기준 업데이트
    if msg_id:
        cur.execute("SELECT id FROM email_excuses WHERE msg_id=?", (msg_id,))
        row = cur.fetchone()
        if row:
            cur.execute("""
                UPDATE email_excuses
                   SET student_id=?,
                       session_date=?,
                       excuse_type=?,
                       evidence_ok=?,
                       notes=?,
                       ai_label=?,
                       ai_confidence=?,
                       ai_reason=?
                 WHERE id=?""",
                (student_id, session_date, excuse_type, int(bool(evidence_ok)),
                 notes, ai_label, ai_confidence, ai_reason, row["id"]))
            conn.commit(); conn.close()
            return "updated_by_msgid"

    # 2) student_id + session_date 기준 업데이트
    cur.execute("SELECT id FROM email_excuses WHERE student_id=? AND session_date=?",
                (student_id, session_date))
    row = cur.fetchone()
    if row:
        cur.execute("""
            UPDATE email_excuses
               SET excuse_type=?,
                   evidence_ok=?,
                   notes=?,
                   msg_id=COALESCE(?, msg_id),
                   ai_label=?,
                   ai_confidence=?,
                   ai_reason=?
             WHERE id=?""",
            (excuse_type, int(bool(evidence_ok)), notes, msg_id,
             ai_label, ai_confidence, ai_reason, row["id"]))
        conn.commit(); conn.close()
        return "updated_by_pair"

    # 3) 신규
    try:
        cur.execute("""
            INSERT INTO email_excuses(student_id, session_date, excuse_type, evidence_ok, notes, msg_id, ai_label, ai_confidence, ai_reason)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (student_id, session_date, excuse_type, int(bool(evidence_ok)), notes,
             msg_id, ai_label, ai_confidence, ai_reason))
        conn.commit(); conn.close()
        return "inserted"
    except Exception:
        # 유니크 충돌 시 msg_id 기준으로 재시도
        if msg_id:
            cur.execute("SELECT id FROM email_excuses WHERE msg_id=?", (msg_id,))
            row = cur.fetchone()
            if row:
                cur.execute("""
                    UPDATE email_excuses
                       SET student_id=?,
                           session_date=?,
                           excuse_type=?,
                           evidence_ok=?,
                           notes=?,
                           ai_label=?,
                           ai_confidence=?,
                           ai_reason=?
                     WHERE id=?""",
                    (student_id, session_date, excuse_type, int(bool(evidence_ok)),
                     notes, ai_label, ai_confidence, ai_reason, row["id"]))
                conn.commit(); conn.close()
                return "updated_after_conflict"
        conn.close()
        return "skipped"

# =========================
# Gmail API
# =========================
def get_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CRED_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w', encoding='utf-8') as f:
            f.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def search_messages(service, query, newer_than_days):
    q0 = (query or '').strip()
    parts = []
    if q0: parts.append(q0)
    if newer_than_days: parts.append(f'newer_than:{newer_than_days}d')
    q = ' '.join(parts).strip()
    msgs = []
    res = service.users().messages().list(userId='me', q=q, labelIds=['INBOX'], maxResults=100).execute()
    if res.get('messages'): msgs.extend(res['messages'])
    while 'nextPageToken' in res:
        res = service.users().messages().list(userId='me', q=q, labelIds=['INBOX'], maxResults=100, pageToken=res['nextPageToken']).execute()
        if res.get('messages'): msgs.extend(res['messages'])
        else: break
    if not msgs:
        res = service.users().messages().list(userId='me', q=q, maxResults=100).execute()
        if res.get('messages'): msgs.extend(res['messages'])
    if not msgs and newer_than_days and newer_than_days < 7:
        q2 = (q0 + ' newer_than:7d').strip()
        res = service.users().messages().list(userId='me', q=q2, labelIds=['INBOX'], maxResults=100).execute()
        if res.get('messages'): msgs.extend(res['messages'])
    return msgs

def get_message(service, msg_id):
    return service.users().messages().get(userId='me', id=msg_id, format='full').execute()

def _pad_b64(s):
    s = s or ""
    return s + "=" * (-len(s) % 4)

def decode_b64(s):
    try:
        return base64.urlsafe_b64decode(_pad_b64(s)).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def strip_html(s):
    if not s: return ''
    s = re.sub(r'(?is)<script.*?>.*?</script>', ' ', s)
    s = re.sub(r'(?is)<style.*?>.*?</style>', ' ', s)
    s = re.sub(r'(?is)<[^>]+>', ' ', s)
    s = html.unescape(s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def extract_text(payload):
    texts, htmls = [], []
    def walk(part):
        mime = (part.get('mimeType') or '').lower()
        body = part.get('body') or {}
        data = body.get('data')
        if data:
            if 'text/plain' in mime:
                texts.append(decode_b64(data))
            elif 'text/html' in mime:
                htmls.append(strip_html(decode_b64(data)))
        for p in part.get('parts') or []:
            walk(p)
    walk(payload or {})
    t = '\n'.join(texts).strip()
    h = '\n'.join(htmls).strip()
    return (t + "\n" + h).strip() if (t and h) else (t or h)

def collect_attachments_meta(msg):
    items = []
    def walk(p):
        body = p.get('body',{}) or {}
        fn = p.get('filename')
        att_id = body.get('attachmentId')
        if att_id:
            items.append((fn or 'attachment', att_id))
        for c in p.get('parts',[]) or []:
            walk(c)
    walk(msg.get('payload', {}))
    return items

def save_attachments(service, msg):
    saved_paths = []
    os.makedirs(ATTACH_DIR, exist_ok=True)
    att_list = collect_attachments_meta(msg)
    if not att_list: return saved_paths
    outdir = os.path.join(ATTACH_DIR, msg['id'])
    os.makedirs(outdir, exist_ok=True)
    for (fn, att_id) in att_list[:5]:
        att = service.users().messages().attachments().get(userId='me', messageId=msg['id'], id=att_id).execute()
        raw = att.get('data','')
        try:
            data = base64.urlsafe_b64decode(_pad_b64(raw))
        except Exception:
            continue
        safe = (fn or 'attachment').replace('/', '_').replace('\\','_')
        p = os.path.join(outdir, safe if safe else 'attachment')
        i, basep = 1, p
        while os.path.exists(p):
            p = f"{basep}_{i}"; i += 1
        with open(p, 'wb') as f:
            f.write(data)
        saved_paths.append(p)
    return saved_paths


# =========================
# Gemini (선택)
# =========================
def configure_gemini():
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key:
        raise RuntimeError("GEMINI_API_KEY가 설정되지 않았습니다. 환경변수로 API 키를 넣어주세요.")
    try:
        import google.generativeai as genai
    except Exception as e:
        raise RuntimeError("google-generativeai 패키지를 설치하세요: pip install google-generativeai") from e

    genai.configure(api_key=key)

    candidates = [
        GEMINI_MODEL_ENV or "models/gemini-2.5-flash",
        "models/gemini-2.0-flash",
        "models/gemini-flash-lite-latest",
        "models/gemini-2.0-flash-lite",
    ]
    last_err = None
    for mid in candidates:
        try:
            model = genai.GenerativeModel(
                mid,
                generation_config={"temperature":0.2, "response_mime_type":"application/json"},
            )
            return model, genai
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"Gemini 모델 초기화 실패: {last_err}")



def _extract_json_block(txt):
    if not txt: return None
    m = re.search(r'```(?:json)?\s*({.*?})\s*```', txt, re.S | re.I)
    if not m:
        m = re.search(r'\{.*\}', txt, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1 if m.lastindex else 0))
    except Exception:
        return None

def _pick_text_from_resp(resp):
    pf = getattr(resp, "prompt_feedback", None)
    if pf and getattr(pf, "block_reason", None):
        return ""
    txt = (getattr(resp, "text", "") or "").strip()
    if txt:
        return txt
    out = []
    try:
        for c in (getattr(resp, "candidates", []) or []):
            content = getattr(c, "content", None)
            parts = getattr(content, "parts", []) if content else []
            for p in parts:
                t = getattr(p, "text", None)
                if t:
                    out.append(str(t))
    except Exception:
        pass
    return "\n".join(out).strip()

def analyze_with_gemini(model, genai, subject, body, attachment_paths, msg_id=None):
    def _clip(s, n=8000):
        s = s or ""
        return s if len(s) <= n else s[:n]

    attachment_block = "\n".join(attachment_paths or [])

    if not model:
        text_blob = "\n".join(filter(None, [subject, body, attachment_block]))
        etype = infer_excuse(text_blob, [os.path.basename(p) for p in (attachment_paths or [])])
        return {
            "student_id": "",
            "session_date": "",
            "excuse_type": etype,
            "evidence_ok": bool(attachment_paths),
            "reason": "heuristic-fallback",
            "confidence": 0.2,
        }

    instruction = (
        "You are an assistant for managing university class attendance. "
        "Decide whether the email discusses class attendance, absence, tardiness, or documentation that excuses a student. "
        "If the message is NOT about attendance or does not justify an absence, respond exactly with "
        '{"student_id":"","session_date":"","excuse_type":"기타","evidence_ok":false,"reason":"not_attendance","confidence":0.0"} '
        "Otherwise respond with a single JSON object using this schema: "
        '{"student_id":"","session_date":"","excuse_type":"","evidence_ok":false,"reason":"","confidence":0.0"} '
        "Only set excuse_type to the Korean labels 공결 or 병결 when appropriate. Dates must be YYYY-MM-DD. "
        "Set evidence_ok to true only when the message or its attachments clearly provide proof. "
        "Keep reason short (<=120 chars) and explain why the excuse should be accepted. "
        "Email newsletters, hiring announcements, product promotions, marketing campaigns, or service notifications must be treated as not_attendance. "
        "Return JSON only with no additional commentary."
    )
    prompt = (
        instruction
        + "\n- Ignore newsletters, promotional content, and generic announcements unless they clearly excuse a student's attendance."
        + "\n- If the message does not reference attendance keywords (출석, 결석, 공결, 병결, 지각, absence, attendance, excused, tardy, sick note, doctor's note, etc.), choose the not_attendance response."
        + "\n- If you cannot find a student identifier or an attendance date, respond with the not_attendance JSON."
        + "\n- Treat recruitment notices, advertising, coupons, sales, product launches, login alerts, festival invitations, and sponsorship offers as not_attendance."
        + "\n\n[Subject]\n"
        + _clip(subject, 2000)
        + "\n\n[Body]\n"
        + _clip(body, 12000)
    )
    if attachment_block:
        prompt += "\n\n[Attachments]\n" + _clip(attachment_block, 4000)

    uploads = []
    if GEMINI_ATTACH and genai:
        try:
            for p in (attachment_paths or [])[:3]:
                try:
                    uploads.append(genai.upload_file(p))
                except Exception:
                    continue
        except Exception:
            pass

    try:
        resp = model.generate_content([prompt] + uploads, generation_config={"temperature": 0.2, "response_mime_type": "application/json"})
        txt = _pick_text_from_resp(resp)
        try:
            return json.loads(txt)
        except Exception:
            data = _extract_json_block(txt)
            if data is not None:
                return data
    except Exception:
        pass

    try:
        resp = model.generate_content(prompt, generation_config={"temperature": 0.2, "response_mime_type": "application/json"})
        txt = _pick_text_from_resp(resp)
        try:
            return json.loads(txt)
        except Exception:
            data = _extract_json_block(txt)
            if data is not None:
                return data
    except Exception:
        pass

    etype = infer_excuse("\n".join(filter(None, [subject, body])), [os.path.basename(p) for p in (attachment_paths or [])])
    return {
        "student_id": "",
        "session_date": "",
        "excuse_type": etype,
        "evidence_ok": bool(attachment_paths),
        "reason": "AI-parse-fallback",
        "confidence": 0.0,
    }


# =========================
# 규칙기반 보정
# =========================
def infer_excuse(text, filenames):
    t = (text or '') + ' ' + ' '.join(filenames or [])
    if any(k in t for k in ['병결','진단서','의사소견서','확인서(병원)']):
        return '병결'
    if any(k in t for k in ['공결','대회','참가확인서','학회','공식행사']):
        return '공결'
    return '기타'

def extract_sid_from_text_like(text):
    if not text:
        return None
    m = STUDENT_ID_REGEX.search(text)
    return m.group(0) if m else None


def extract_sid_from_filenames(paths):
    for p in paths or []:
        name = os.path.splitext(os.path.basename(p))[0]
        sid = extract_sid_from_text_like(name)
        if sid:
            return sid
    return None

def student_exists(sid):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT 1 FROM students WHERE id=?", (sid,))
    ok = cur.fetchone() is not None
    conn.close()
    return ok


def extract_text_from_pdfs(paths, limit_bytes=5_000_000):
    text = []
    try:
        import PyPDF2
    except Exception:
        return ''
    for p in paths or []:
        try:
            if not p.lower().endswith('.pdf'): continue
            if os.path.getsize(p) > limit_bytes: continue
            with open(p, 'rb') as f:
                r = PyPDF2.PdfReader(f)
                for i in range(min(len(r.pages), 5)):
                    try:
                        text.append(r.pages[i].extract_text() or '')
                    except Exception:
                        continue
        except Exception:
            continue
    return '\n'.join(text)

# =========================
# 메인 파이프라인
# =========================
def run(query, newer_than_days, override_date=None):
    service = get_service()

    model = None
    genai = None
    gemini_available = False
    if GEMINI_ON:
        try:
            model, genai = configure_gemini()
            gemini_available = True
        except Exception as exc:
            print(f"[WARN] Gemini unavailable: {exc}")
            gemini_available = False
    msgs = search_messages(service, query, newer_than_days)
    found = len(msgs); upserted = 0; sid_missing = 0
    invalid_sid = 0; skipped = 0; failed = 0
    touched_dates = set()

    sid_pat = re.compile(r'\b(20\d{2})11(\d{3})\b')

    def _student_exists(sid):
        conn = db(); cur = conn.cursor()
        cur.execute("SELECT 1 FROM students WHERE id=?", (sid,))
        ok = cur.fetchone() is not None
        conn.close()
        return ok

    for m in msgs:
        try:
            full = get_message(service, m['id'])
            subj = get_subject(full)
            body = extract_text(full.get('payload', {})) or ''
            snippet = full.get('snippet', '') or ''
            emails, names = extract_addresses_and_names(full)
            paths = save_attachments(service, full)
            pdf_text = extract_text_from_pdfs(paths)
            big_text = '\n'.join([subj or '', body or '', snippet or '', pdf_text or '', ' '.join(names or [])]).strip()

            keyword_sources = [
                subj, body, snippet, pdf_text,
                " ".join(names or []),
                " ".join(emails or []),
                " ".join(os.path.basename(p) for p in (paths or [])),
            ]
            if not _contains_attendance_keyword(*keyword_sources):
                skipped += 1
                continue

            combined_text = " ".join(filter(None, keyword_sources)).lower()
            positive_terms = ["출석", "결석", "공결", "병결", "attendance", "absence", "excuse", "지각", "병원", "진단서", "지각"]
            advertising_terms = [
                "채용", "채용공고", "취업", "모집", "채용 안내", "광고", "홍보", "프로모션",
                "마케팅", "세일", "할인", "쿠폰", "로그인", "가입", "구독", "페스티벌",
                "festival", "event", "이벤트", "행사", "프로그램 안내", "재홍보", "광고입니다",
                "promotion", "newsletter", "광고성", "신규 서비스"
            ]
            ad_hit = any(term in combined_text for term in advertising_terms)

            ai = analyze_with_gemini(model, genai, subj, (body or snippet), paths, msg_id=m['id'])
            if isinstance(ai, list):
                ai = ai[0] if ai and isinstance(ai[0], dict) else {}
            elif not isinstance(ai, dict):
                ai = {}

            sid = None; d = None
            etype_raw = (ai.get("excuse_type") or "").strip()
            etype = etype_raw if etype_raw in ("공결", "병결") else "기타"
            reason = (ai.get("reason") or "").strip()[:180]
            try:
                conf = float(ai.get("confidence") or 0.0)
            except Exception:
                conf = 0.0
            evidence = 1 if (ai.get("evidence_ok") or paths) else 0

            if ai.get("student_id"):
                sid = str(ai["student_id"]).strip()
            if not sid:
                sid = extract_sid_from_text_like("\n".join([subj or '', body or '', snippet or '']))
            if not sid and paths:
                sid = extract_sid_from_filenames(paths)
            if not sid and pdf_text:
                sid = extract_sid_from_text_like(pdf_text)
            if not sid and names:
                sid = extract_sid_from_text_like(' '.join(names))
            if not sid and emails:
                for a in emails:
                    sid = extract_sid_from_text_like(a.split('@',1)[0])
                    if sid: break
            if not sid and emails:
                for a in emails:
                    sid = lookup_student_id_by_email(a)
                    if sid: break
            if sid: sid = str(sid)

            if not d:
                try:
                    ts = int(full.get('internalDate', 0)) / 1000.0
                    d = datetime.datetime.fromtimestamp(ts).date().isoformat()
                except Exception:
                    d = None

            if override_date:
                d = override_date
            if not d:
                try:
                    ts = int(full.get('internalDate', 0)) / 1000.0
                    d = datetime.datetime.fromtimestamp(ts).date().isoformat()
                except Exception:
                    d = None

            if not etype or etype == "기타":
                guess = infer_excuse(big_text, [os.path.basename(p) for p in paths])
                if guess in ("공결", "병결"):
                    etype = guess

            has_kw = _contains_attendance_keyword(subj, body, snippet, pdf_text, reason)

            if not sid or not STUDENT_ID_REGEX.fullmatch(str(sid)):
                sid_missing += 1
                continue

            if not d:
                skipped += 1
                continue

            reason_lower = reason.lower()

            valid_excuse = etype in ("공결", "병결")
            if not valid_excuse:
                skipped += 1
                continue

            if not has_kw and "출석" not in reason_lower and "attendance" not in reason_lower:
                skipped += 1
                continue

            if "not_attendance" in reason_lower:
                skipped += 1
                continue

            positive_hit = any(term in combined_text for term in positive_terms) or any(term in reason_lower for term in positive_terms)
            if ad_hit and not positive_hit:
                skipped += 1
                continue

            if any(term in reason_lower for term in advertising_terms):
                skipped += 1
                continue

            upsert(
                sid, d, etype, 1 if evidence else 0, reason,
                msg_id=m['id'], ai_label=etype, ai_confidence=conf, ai_reason=reason
            )
            upserted += 1
            if d:
                touched_dates.add(d)

        except Exception as e:
            failed += 1
            try:
                print(f"[ERROR][{m.get('id')}] {type(e).__name__}: {e}")
            except Exception:
                pass
            continue

    return found, upserted, sid_missing, invalid_sid, skipped, failed, gemini_available, sorted(touched_dates)


def export_excuses_to_csv(db_path="backend/attendai.db"):
    import sqlite3
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM excuses ORDER BY received_at DESC")
    rows = cursor.fetchall()
    headers = [desc[0] for desc in cursor.description]

    export_dir = Path("backend/exports")
    export_dir.mkdir(exist_ok=True)
    export_path = export_dir / "excuses.csv"

    with open(export_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    conn.close()
    print(f"[INFO] 공결 CSV 갱신 완료 → {export_path}")
    
# =========================
# CLI
# =========================
if __name__ == '__main__':
    a = argparse.ArgumentParser()
    a.add_argument('--query', default='')
    a.add_argument('--days', type=int, default=30)  # 기본 30일
    args = a.parse_args()
    print("processed:", run(args.query, args.days))
