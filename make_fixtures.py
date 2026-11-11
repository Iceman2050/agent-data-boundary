"""Build the synthetic mini agent system used by the demo and the tests.

ALL data is obviously synthetic: fake names, example.com addresses, 555
phone numbers, and the well-known Luhn-valid test card number. One synthetic
subject ("Test Subject A", subj-test-a / testa@example.com) is planted in
the sqlite, json and logs stores and deliberately NOT in the jsonl store.
One config entry points at a missing file so reports demonstrate the
INACCESSIBLE state for real.

Usage: python make_fixtures.py [target_dir]   (default: ./fixtures)
"""
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

SUBJECT_EMAIL = "testa@example.com"
SUBJECT_ID = "subj-test-a"


def build(root):
    os.makedirs(root, exist_ok=True)
    now = datetime.now(timezone.utc)
    recent = (now - timedelta(days=5)).isoformat()
    old = (now - timedelta(days=400)).isoformat()

    db = os.path.join(root, "conversations.sqlite")
    if os.path.exists(db):
        os.remove(db)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE conversations (id INTEGER PRIMARY KEY, "
                 "subject_id TEXT, email TEXT, body TEXT, created_at TEXT)")
    conn.executemany(
        "INSERT INTO conversations VALUES (?,?,?,?,?)",
        [(1, SUBJECT_ID, SUBJECT_EMAIL,
          "Test Subject A asked about billing. Card on file noted as "
          "4012888888881881 in this synthetic fixture.", recent),
         (2, "subj-other", "other@example.com",
          "Unrelated synthetic conversation.", recent),
         (3, "subj-other", "other@example.com",
          "Very old synthetic conversation kept past policy.", old)])
    conn.commit()
    conn.close()

    with open(os.path.join(root, "memory.jsonl"), "w", encoding="utf-8") as fh:
        # Subject A is deliberately NOT in this store.
        fh.write(json.dumps({"id": "mem-1", "subject_id": "subj-test-b",
                             "email": "testb@example.com",
                             "text": "Synthetic memory for Test Subject B.",
                             "created_at": recent}) + "\n")
        fh.write(json.dumps({"id": "mem-2", "subject_id": "subj-other",
                             "text": "Synthetic ops note: worker at 192.168.1.20 "
                                     "processed the export.",
                             "created_at": recent}) + "\n")

    with open(os.path.join(root, "vectors.json"), "w", encoding="utf-8") as fh:
        json.dump({"records": [
            {"id": "vec-1", "subject_id": SUBJECT_ID, "email": SUBJECT_EMAIL,
             "chunk": "Synthetic RAG chunk mentioning Test Subject A and "
                      "testa@example.com.", "created_at": recent},
            {"id": "vec-2", "subject_id": "subj-other",
             "chunk": "Unrelated synthetic chunk.", "created_at": recent},
        ]}, fh, indent=2)

    logs = os.path.join(root, "logs")
    os.makedirs(logs, exist_ok=True)
    with open(os.path.join(logs, "agent.log"), "w", encoding="utf-8") as fh:
        fh.write("2026-01-01 INFO synthetic startup line\n")
        fh.write("2026-01-01 INFO handled request for %s (%s)\n"
                 % (SUBJECT_EMAIL, SUBJECT_ID))
        fh.write("2026-01-01 INFO handled request for other@example.com\n")

    config = {"stores": [
        {"name": "conversations", "type": "sqlite",
         "path": "conversations.sqlite", "table": "conversations",
         "retention_days": 90, "retention_basis": "demo policy: chat data kept 90 days",
         "deletion_test_safe": True},
        {"name": "memory-export", "type": "jsonl", "path": "memory.jsonl",
         "retention_days": 90, "retention_basis": "demo policy: memory exports kept 90 days",
         "deletion_test_safe": True},
        {"name": "vector-store", "type": "json", "path": "vectors.json",
         "retention_days": 90, "retention_basis": "demo policy: RAG chunks kept 90 days",
         "deletion_test_safe": False},
        {"name": "logs", "type": "textdir", "path": "logs",
         "retention_days": None, "retention_basis": "no declared retention in demo",
         "deletion_test_safe": True},
        {"name": "missing-export", "type": "jsonl", "path": "does-not-exist.jsonl",
         "retention_days": 90, "retention_basis": "demo policy",
         "deletion_test_safe": True},
    ]}
    cfg_path = os.path.join(root, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)
    return cfg_path


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixtures")
    print(build(target))
