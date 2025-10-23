# -*- coding: utf-8 -*-
import os, sqlite3, base64, re, datetime, argparse, json, html
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from email.header import decode_header, make_header
from email.utils import getaddresses

# =========================
# 기본 설정
# =========================
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
BASE = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE, 'attendai.db')
CRED_FILE = os.path.join(BASE, 'credentials.json')
TOKEN_FILE = os.path.join(BASE, 'gmail_token.json')
ATTACH_DIR = os.path.join(BASE, 'attachments')

# AI 토글/한도(환경변수)
GEMINI_ON = os.getenv("GEMINI_ON", "0") == "1"
GEMINI_MODEL_ENV = (os.getenv("GEMINI_MODEL") or "").strip()
GEMINI_MAX_CALLS = int(os.getenv("GEMINI_MAX_CALLS", "5"))
GEMINI_ATTACH = os.getenv("GEMINI_ATTACH", "0") == "1"  # 기본 첨부 업로드 비활성(안정)

# 규칙 기반 키워드
AI_KEYWORDS = ["공결","병결","진단서","의사소견서","참가확인서","대회","학회","공식행사","결석계","결석 사유"]

PROMPT = """당신은 메일 분류기입니다. 결과는 반드시 JSON '한 덩어리'만 출력합니다.
어떠한 설명/코드블록/주석/추가텍스트도 출력하지 마세요.

필드:
- student_id: 학번(숫자만). 모르겠으면 "" (빈 문자열)
- session_date: YYYY-MM-DD. 모르겠으면 ""
- excuse_type: "공결" | "병결" | "기타" 중 하나
- evidence_ok: 첨부/본문 근거로 증빙이 있으면 true, 아니면 false
- reason: 판단 근거(최대 300자, 개조식 OK)
- confidence: 0.0 ~ 1.0

출력 예시(예시는 그대로 출력하지 말고 실제 값으로 채워서 출력):
{"student_id":"","session_date":"","excuse_type":"기타","evidence_ok":false,"reason":"","confidence":0.5}
"""

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

def decode_b64(s):
    return base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')

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
        mime = part.get('mimeType','')
        body = part.get('body',{}) or {}
        data = body.get('data')
        if data:
            if mime == 'text/plain':
                texts.append(decode_b64(data))
            elif mime == 'text/html':
                htmls.append(strip_html(decode_b64(data)))
        for p in part.get('parts',[]) or []:
            walk(p)
    walk(payload)
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
        data = base64.urlsafe_b64decode(att['data'])
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
    if not GEMINI_ON:
        print("[AI] Gemini OFF (rule-based only)")
        return None, None
    key = os.getenv("GEMINI_API_KEY", "")
    if not key:
        print("[DEBUG] no GEMINI_API_KEY in env")
        return None, None
    try:
        import google.generativeai as genai
    except Exception as e:
        print("[DEBUG] import google.generativeai failed:", repr(e))
        return None, None
    try:
        genai.configure(api_key=key)
    except TypeError:
        # 일부 버전에서 api_version 인자를 허용하지 않음
        genai.configure(api_key=key)

    candidates = [
        GEMINI_MODEL_ENV or "models/gemini-2.0-flash-lite",
        "models/gemini-flash-lite-latest",
        "models/gemini-2.0-flash",
        "models/gemini-2.5-flash",
    ]
    print("[DEBUG] GEMINI candidates:", candidates)
    for mid in candidates:
        try:
            model = genai.GenerativeModel(
                mid,
                generation_config={"temperature":0.2, "response_mime_type":"application/json"},
            )
            print(f"[DEBUG] GEMINI_MODEL={mid}")
            return model, genai
        except Exception as e:
            print(f"[DEBUG] model init fail for {mid}:", repr(e))
            continue
    print("[DEBUG] no working GEMINI model among candidates")
    return None, None

def _extract_json_block(txt):
    if not txt:
        return None
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
    # 다양한 응답 구조에서 텍스트를 안전히 뽑는다.
    pf = getattr(resp, "prompt_feedback", None)
    if pf and getattr(pf, "block_reason", None):
        print(f"[GEMINI] blocked:", pf.block_reason)
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
                data = getattr(p, "data", None)
                if data:
                    try:
                        out.append(data.decode("utf-8","ignore")
                                   if isinstance(data,(bytes,bytearray)) else str(data))
                    except Exception:
                        pass
    except Exception:
        pass
    return "\n".join(out).strip()

def should_send_to_gemini(subject, body, filepaths):
    t = f"{subject or ''}\n{body or ''}"
    has_kw = any(k in t for k in AI_KEYWORDS)
    has_probable_evidence = any(
        any(k in os.path.basename(p).lower() for k in ["pdf","jpg","jpeg","png","hwp","doc","docx"])
        for p in (filepaths or [])
    )
    return bool(has_kw or has_probable_evidence)

def analyze_with_gemini(model, genai, subject, body, attachment_paths, msg_id=None):
    def _clip(s, n=8000):
        s = s or ""
        return s if len(s) <= n else s[:n]

    # 단일 문자열 프롬프트로 전달 (리스트 대신)
    instr = (
        "아래 이메일 정보를 분석해 **JSON 객체 한 개만** 출력하세요.\n"
        "설명/코드블록/추가텍스트 금지. 반드시 '{'로 시작하고 '}'로 끝납니다.\n"
        '키: {"student_id":"","session_date":"","excuse_type":"공결|병결|기타","evidence_ok":true/false,"reason":"","confidence":0.0}\n'
        "출력 외의 텍스트는 절대 포함하지 마세요."
    )
    prompt = (
        instr + "\n\n"
        + "[제목]\n" + _clip(subject, 2000) + "\n\n"
        + "[본문]\n" + _clip(body, 12000)
    )

    # 첨부 업로드는 기본 비활성(GEMINI_ATTACH=1일 때만 업로드 시도)
    uploads = []
    if GEMINI_ATTACH:
        for p in (attachment_paths[:3] or []):
            try:
                uploads.append(genai.upload_file(p))
            except Exception:
                pass

    def _extract_json_block(txt):
        if not txt:
            return None
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
            print(f"[GEMINI] blocked:", pf.block_reason)
            return ""
        txt = (getattr(resp, "text", "") or "").strip()
        if txt:
            return txt
        # 후보 파트에서 긁어오기
        try:
            out = []
            for c in (getattr(resp, "candidates", []) or []):
                content = getattr(c, "content", None)
                parts = getattr(content, "parts", []) if content else []
                for p in parts:
                    t = getattr(p, "text", None)
                    if t:
                        out.append(str(t))
            return "\n".join(out).strip()
        except Exception:
            return ""

    # 1) 첨부 포함 시도
    try:
        resp = model.generate_content(
            [prompt] + uploads,
            generation_config={"temperature":0.2,"response_mime_type":"application/json"},
        )
        txt = _pick_text_from_resp(resp)
        # 디버그: 응답 앞부분 저장
        if txt:
            try:
                logdir = os.path.join(BASE, "attachments", "_ai_logs")
                os.makedirs(logdir, exist_ok=True)
                with open(os.path.join(logdir, f"{(msg_id or 'noid')}.txt"),
                          "w", encoding="utf-8") as f:
                    f.write(txt[:2048])
            except Exception:
                pass
        try:
            return json.loads(txt)
        except Exception:
            pass
        data = _extract_json_block(txt)
        if data is not None:
            return data
    except Exception as e:
        s = str(e)
        if "Quota exceeded" in s or "ResourceExhausted" in s:
            raise
        print("[GEMINI] call-1 failed:", repr(e))

    # 2) 첨부 없이 재시도
    try:
        resp = model.generate_content(
            prompt,
            generation_config={"temperature":0.2,"response_mime_type":"application/json"},
        )
        txt = _pick_text_from_resp(resp)
        try:
            return json.loads(txt)
        except Exception:
            pass
        data = _extract_json_block(txt)
        if data is not None:
            return data
    except Exception as e:
        s = str(e)
        if "Quota exceeded" in s or "ResourceExhausted" in s:
            raise
        print("[GEMINI] call-2 failed:", repr(e))

    # 3) 끝까지 실패 시, 규칙기반용 기본 JSON 만들어 반환(파이프라인 끊기지 않도록)
    return {
        "student_id": "",
        "session_date": "",
        "excuse_type": "기타",
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
    if not text: return None
    cand = re.findall(r'\d{8,10}', text)
    for s in cand:
        if s.startswith('20') or s.startswith('19'):
            return s
    if cand:
        return cand[0]
    for tok in re.findall(r'[0-9\-\._ ]{8,20}', text):
        d = re.sub(r'\D','', tok)
        if 8 <= len(d) <= 10:
            if d.startswith('20') or d.startswith('19'):
                return d
            return d
    return None

def extract_sid_from_filenames(paths):
    for p in paths or []:
        name = os.path.splitext(os.path.basename(p))[0]
        sid = extract_sid_from_text_like(name)
        if sid: return sid
    return None

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
def run(query, newer_than_days):
    service = get_service()
    model, genai = configure_gemini()
    print(f"[DEBUG] GEMINI_ACTIVE={bool(model)}  MAX_CALLS={GEMINI_MAX_CALLS}")

    msgs = search_messages(service, query, newer_than_days)
    found = len(msgs)
    upserted = 0
    sid_missing = 0
    ai_calls = 0

    for m in msgs:
        try:
            full = get_message(service, m['id'])
            subj = get_subject(full)
            body = extract_text(full.get('payload',{})) or ''
            snippet = full.get('snippet','') or ''
            emails, names = extract_addresses_and_names(full)
            paths = save_attachments(service, full)

            pdf_text = extract_text_from_pdfs(paths)
            big_text = '\n'.join([subj or '', body or '', snippet or '', pdf_text or '', ' '.join(names or [])]).strip()

            # ===== AI 호출 (선별 + 호출수 제한)
            ai = None
            if model and genai and ai_calls < GEMINI_MAX_CALLS and should_send_to_gemini(subj, (body or snippet), paths):
                try:
                    ai = analyze_with_gemini(model, genai, subj, (body or snippet), paths, msg_id=m['id'])
                    ai_calls += 1
                except Exception as e:
                    msg = str(e)
                    if "Quota exceeded" in msg or "ResourceExhausted" in msg:
                        print("[GEMINI] quota hit; disabling AI for remaining messages")
                        model = None  # 이후 전부 규칙기반
                        ai = None
                    else:
                        print("[GEMINI] exception:", repr(e))
                        ai = None

            # ===== 필드 채우기
            sid = None; d = None; etype = None
            evidence = 1 if paths else 0
            reason = ''; conf = None

            if ai:
                sid = (ai.get("student_id") or None)
                d   = (ai.get("session_date") or None)
                etype = ai.get("excuse_type") or None
                evidence = 1 if ai.get("evidence_ok") else evidence
                reason = (ai.get("reason") or "")[:300]
                try:
                    conf = float(ai.get("confidence") or 0.0)
                except Exception:
                    conf = 0.0
                print(f"[GEMINI] id={m['id']} sid={sid} date={d} type={etype} conf={conf:.2f}")

            if not sid:
                sid = extract_sid_from_text_like('\n'.join([subj or '', body or '', snippet or '']))
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

            if not etype:
                etype = infer_excuse(big_text, [os.path.basename(p) for p in paths])

            if not d:
                try:
                    ts = int(full.get('internalDate', 0)) / 1000.0
                    d = datetime.datetime.fromtimestamp(ts).date().isoformat()
                except Exception:
                    d = None

            if sid and d and etype:
                upsert(sid, d, etype, evidence, reason,
                       msg_id=m['id'],
                       ai_label=(etype if ai else None),
                       ai_confidence=conf if ai else None,
                       ai_reason=reason)
                upserted += 1
            else:
                sid_missing += 1
        except Exception:
            # 개별 메시지 실패는 전체 파이프라인에 영향 주지 않음
            continue
    return found, upserted, sid_missing

# =========================
# CLI
# =========================
if __name__ == '__main__':
    a = argparse.ArgumentParser()
    a.add_argument('--query', default='')
    a.add_argument('--days', type=int, default=30)  # 기본 30일
    args = a.parse_args()
    print("processed:", run(args.query, args.days))
