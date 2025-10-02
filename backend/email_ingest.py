import os
import json
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "attendai.db")
EML_DIR = os.path.join(os.path.dirname(__file__), "emails")

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def upsert(student_id, session_date, excuse_type, evidence_ok, notes, msg_id=None):
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


def main():
    if not os.path.isdir(EML_DIR):
        return
    files = [f for f in os.listdir(EML_DIR) if f.endswith(".json")]
    for f in files:
        p = os.path.join(EML_DIR, f)
        with open(p, "r", encoding="utf-8") as fh:
            j = json.load(fh)
        sid = str(j.get("student_id","")).strip()
        d = str(j.get("session_date","")).strip()
        t = str(j.get("excuse_type","")).strip()
        e = 1 if bool(j.get("evidence_ok", False)) else 0
        n = str(j.get("notes","")).strip()
        if sid and d and t:
            upsert(sid, d, t, e, n)

if __name__ == "__main__":
    main()
