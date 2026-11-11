"""Local store adapters: sqlite, jsonl, json, textdir. Local files only.

Every adapter exposes:
  probe()            -> (accessible: bool, reason: str)
  records()          -> list of {record_id, text, timestamp (ISO str|None)}
  delete_matching(ids, identifiers) -> count removed (used ONLY on copies)
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

_TS_KEYS = ("created_at", "timestamp", "ts", "time", "date")


def _ts_from(obj):
    if isinstance(obj, dict):
        for k in _TS_KEYS:
            v = obj.get(k)
            if isinstance(v, str) and v:
                return v
    return None


def _text_of(obj):
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, default=str, sort_keys=True)


class StoreError(Exception):
    pass


class BaseStore:
    def __init__(self, cfg):
        self.cfg = cfg
        self.name = cfg["name"]
        self.path = cfg["path"]

    def probe(self):
        raise NotImplementedError

    def records(self):
        raise NotImplementedError

    def delete_matching(self, record_ids):
        raise NotImplementedError


class SqliteStore(BaseStore):
    def _table(self, conn):
        if self.cfg.get("table"):
            return self.cfg["table"]
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
        if not rows:
            raise StoreError("no user tables in sqlite file")
        return rows[0][0]

    def probe(self):
        if not os.path.isfile(self.path):
            return False, "file not found: %s" % self.path
        try:
            conn = sqlite3.connect("file:%s?mode=ro" % self.path, uri=True)
            self._table(conn)
            conn.close()
            return True, "ok"
        except Exception as exc:  # unreadable / not a database
            return False, "sqlite probe failed: %s" % exc

    def records(self):
        conn = sqlite3.connect("file:%s?mode=ro" % self.path, uri=True)
        try:
            table = self._table(conn)
            cur = conn.execute('SELECT rowid, * FROM "%s"' % table)
            cols = [d[0] for d in cur.description]
            out = []
            for row in cur.fetchall():
                obj = dict(zip(cols[1:], row[1:]))
                out.append({"record_id": "%s:%s" % (table, row[0]),
                            "text": _text_of(obj), "timestamp": _ts_from(obj),
                            "_rowid": row[0]})
            return out
        finally:
            conn.close()

    def delete_matching(self, record_ids):
        rowids = [r["_rowid"] for r in self.records()
                  if r["record_id"] in record_ids]
        if not rowids:
            return 0
        conn = sqlite3.connect(self.path)
        try:
            table = self._table(conn)
            conn.executemany('DELETE FROM "%s" WHERE rowid=?' % table,
                             [(i,) for i in rowids])
            conn.commit()
            return conn.total_changes
        finally:
            conn.close()


class JsonlStore(BaseStore):
    def probe(self):
        if not os.path.isfile(self.path):
            return False, "file not found: %s" % self.path
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        json.loads(line)
                        break
            return True, "ok"
        except Exception as exc:
            return False, "jsonl probe failed: %s" % exc

    def _lines(self):
        with open(self.path, encoding="utf-8") as fh:
            return [ln for ln in fh.read().splitlines() if ln.strip()]

    def records(self):
        out = []
        for i, line in enumerate(self._lines()):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = line
            rid = obj.get("id") if isinstance(obj, dict) else None
            out.append({"record_id": str(rid) if rid is not None else "line:%d" % (i + 1),
                        "text": _text_of(obj), "timestamp": _ts_from(obj),
                        "_line": i})
        return out

    def delete_matching(self, record_ids):
        recs = self.records()
        drop = {r["_line"] for r in recs if r["record_id"] in record_ids}
        if not drop:
            return 0
        kept = [ln for i, ln in enumerate(self._lines()) if i not in drop]
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(kept) + ("\n" if kept else ""))
        return len(drop)


class JsonStore(BaseStore):
    def _load(self):
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("records"), list):
            return data, data["records"], True
        if isinstance(data, list):
            return data, data, False
        raise StoreError("json store must be a list or an object with a 'records' list")

    def probe(self):
        if not os.path.isfile(self.path):
            return False, "file not found: %s" % self.path
        try:
            self._load()
            return True, "ok"
        except Exception as exc:
            return False, "json probe failed: %s" % exc

    def records(self):
        _, items, _ = self._load()
        out = []
        for i, obj in enumerate(items):
            rid = obj.get("id") if isinstance(obj, dict) else None
            out.append({"record_id": str(rid) if rid is not None else "index:%d" % i,
                        "text": _text_of(obj), "timestamp": _ts_from(obj),
                        "_index": i})
        return out

    def delete_matching(self, record_ids):
        data, items, wrapped = self._load()
        recs = self.records()
        drop = {r["_index"] for r in recs if r["record_id"] in record_ids}
        if not drop:
            return 0
        kept = [o for i, o in enumerate(items) if i not in drop]
        if wrapped:
            data["records"] = kept
        else:
            data = kept
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return len(drop)


class TextDirStore(BaseStore):
    """A directory of text files; each file is one record (logs folder)."""
    def probe(self):
        if not os.path.isdir(self.path):
            return False, "directory not found: %s" % self.path
        return True, "ok"

    def _files(self):
        return sorted(f for f in os.listdir(self.path)
                      if os.path.isfile(os.path.join(self.path, f)))

    def records(self):
        out = []
        for fname in self._files():
            full = os.path.join(self.path, fname)
            with open(full, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            ts = datetime.fromtimestamp(
                os.path.getmtime(full), tz=timezone.utc).isoformat()
            out.append({"record_id": fname, "text": text, "timestamp": ts,
                        "_file": fname})
        return out

    def delete_matching(self, record_ids):
        # Remove only the lines that contain a matched record's identifiers is
        # not well-defined per-file; the deletion unit here is the whole file
        # record when the caller matched the file. Callers pass identifiers via
        # delete_lines_containing instead for line-level removal.
        raise StoreError("textdir deletion is line-based; use delete_lines_containing")

    def delete_lines_containing(self, identifiers):
        removed = 0
        for fname in self._files():
            full = os.path.join(self.path, fname)
            with open(full, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
            kept = [ln for ln in lines
                    if not any(i in ln for i in identifiers)]
            if len(kept) != len(lines):
                removed += len(lines) - len(kept)
                with open(full, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(kept) + ("\n" if kept else ""))
        return removed


_ADAPTERS = {"sqlite": SqliteStore, "jsonl": JsonlStore,
             "json": JsonStore, "textdir": TextDirStore}


def open_store(cfg):
    return _ADAPTERS[cfg["type"]](cfg)
