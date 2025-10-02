import os, sqlite3, base64, re, datetime, argparse
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

import email
from email.header import decode_header, make_header


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
BASE = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE, 'attendai.db')
CRED_FILE = os.path.join(BASE, 'credentials.json')
TOKEN_FILE = os.path.join(BASE, 'gmail_token.json')
ATTACH_DIR = os.path.join(BASE, 'attachments')

def get_subject(full):
    headers = full.get('payload', {}).get('headers', [])
    for h in headers:
        if h.get('name','').lower() == 'subject':
            return str(make_header(decode_header(h.get('value',''))))
    return ''

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def upsert(student_id, session_date, excuse_type, evidence_ok, notes, msg_id):
    conn = db()
    cur = conn.cursor()
    if msg_id:
        cur.execute("SELECT id FROM email_excuses WHERE msg_id=?", (msg_id,))
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE email_excuses SET student_id=?, session_date=?, excuse_type=?, evidence_ok=?, notes=? WHERE id=?",
                        (student_id, session_date, excuse_type, evidence_ok, notes, row["id"]))
        else:
            cur.execute("INSERT INTO email_excuses(student_id, session_date, excuse_type, evidence_ok, notes, msg_id) VALUES(?,?,?,?,?,?)",
                        (student_id, session_date, excuse_type, evidence_ok, notes, msg_id))
    else:
        cur.execute("SELECT id FROM email_excuses WHERE student_id=? AND session_date=?", (student_id, session_date))
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE email_excuses SET excuse_type=?, evidence_ok=?, notes=? WHERE id=?",
                        (excuse_type, evidence_ok, notes, row["id"]))
        else:
            cur.execute("INSERT INTO email_excuses(student_id, session_date, excuse_type, evidence_ok, notes) VALUES(?,?,?,?,?)",
                        (student_id, session_date, excuse_type, evidence_ok, notes))
    conn.commit()
    conn.close()


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
    q = query
    if newer_than_days:
        q += f' newer_than:{newer_than_days}d'
    res = service.users().messages().list(userId='me', q=q, maxResults=50).execute()
    msgs = []
    while res.get('messages'):
        msgs.extend(res['messages'])
        if 'nextPageToken' in res:
            res = service.users().messages().list(userId='me', q=q, pageToken=res['nextPageToken'], maxResults=50).execute()
        else:
            break
    return msgs

def get_message(service, msg_id):
    return service.users().messages().get(userId='me', id=msg_id, format='full').execute()

def extract_plain(payload):
    texts = []
    def walk(part):
        mime = part.get('mimeType','')
        if mime == 'text/plain' and 'data' in part.get('body',{}):
            data = part['body']['data']
            texts.append(base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore'))
        for p in part.get('parts',[]) or []:
            walk(p)
    walk(payload)
    return '\n'.join(texts)

def save_attachments(service, msg):
    saved = False
    os.makedirs(ATTACH_DIR, exist_ok=True)
    parts = []
    def collect(p):
        if p.get('filename'):
            parts.append(p)
        for c in p.get('parts',[]) or []:
            collect(c)
    collect(msg['payload'])
    for p in parts:
        fn = p.get('filename')
        body = p.get('body',{})
        att_id = body.get('attachmentId')
        if fn and att_id:
            att = service.users().messages().attachments().get(userId='me', messageId=msg['id'], id=att_id).execute()
            data = base64.urlsafe_b64decode(att['data'])
            outdir = os.path.join(ATTACH_DIR, msg['id'])
            os.makedirs(outdir, exist_ok=True)
            with open(os.path.join(outdir, fn), 'wb') as f:
                f.write(data)
            saved = True
    return saved

def parse_fields(text):
    sid = None
    date = None
    etype = None
    notes = ''
    m = re.search(r'(?<!\d)(20\d{6,7}|19\d{6,7}|\d{8})', text)
    if m:
        sid = m.group(1)
    m = re.search(r'(\d{4}[./-]\d{1,2}[./-]\d{1,2})', text)
    if m:
        s = m.group(1).replace('/','-').replace('.','-')
        y,mo,da = [int(x) for x in s.split('-')]
        date = f'{y:04d}-{mo:02d}-{da:02d}'
    else:
        m = re.search(r'(\d{1,2}[./]\d{1,2})', text)
        if m:
            s = m.group(1).replace('.','/').split('/')
            y = datetime.date.today().year
            mo = int(s[0]); da = int(s[1])
            date = f'{y:04d}-{mo:02d}-{da:02d}'
    if '병결' in text:
        etype = '병결'
    elif '공결' in text or '공식' in text or '대회' in text or '참가확인서' in text:
        etype = '공결'
    else:
        etype = '기타'
    notes = text[:120]
    return sid, date, etype, notes

def get_message_id(full):
    headers = full.get('payload', {}).get('headers', [])
    for h in headers:
        if h.get('name','').lower() in ('message-id','messageid','message_id'):
            return h.get('value','').strip()
    return full.get('id')  # Gmail의 내부 id라도 fallback

def run(query, newer_than_days):
    service = get_service()
    msgs = search_messages(service, query, newer_than_days)
    for m in msgs:
        full = get_message(service, m['id'])
        subj = get_subject(full)
        text = extract_plain(full.get('payload',{})) or ''
        text = (subj or '') + "\n" + text
        sid, d, etype, notes = parse_fields(text)
        saved = save_attachments(service, full)
        if not d:
            try:
                ts = int(full.get('internalDate', 0)) / 1000.0
                d = datetime.datetime.fromtimestamp(ts).date().isoformat()
            except Exception:
                d = None
        msg_id = get_message_id(full)
        if sid and d and etype:
            upsert(sid, d, etype, 1 if saved else 0, notes, msg_id)



if __name__ == '__main__':
    a = argparse.ArgumentParser()
    a.add_argument('--query', default='has:attachment (subject:공결 OR 진단서 OR 참가확인서)')
    a.add_argument('--days', type=int, default=14)
    args = a.parse_args()
    run(args.query, args.days)
