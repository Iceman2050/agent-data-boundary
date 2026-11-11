import json

import make_fixtures
from agent_data_boundary.config import load_config
from agent_data_boundary.stores import open_store


def _cfg(tmp_path):
    return load_config(make_fixtures.build(str(tmp_path)))


def _store(config, name):
    return open_store(next(s for s in config["stores"] if s["name"] == name))


def test_sqlite_adapter(tmp_path):
    store = _store(_cfg(tmp_path), "conversations")
    assert store.probe()[0] is True
    recs = store.records()
    assert len(recs) == 3
    assert all(r["timestamp"] for r in recs)


def test_jsonl_adapter(tmp_path):
    store = _store(_cfg(tmp_path), "memory-export")
    recs = store.records()
    assert [r["record_id"] for r in recs] == ["mem-1", "mem-2"]


def test_json_adapter(tmp_path):
    store = _store(_cfg(tmp_path), "vector-store")
    recs = store.records()
    assert [r["record_id"] for r in recs] == ["vec-1", "vec-2"]


def test_textdir_adapter(tmp_path):
    store = _store(_cfg(tmp_path), "logs")
    recs = store.records()
    assert len(recs) == 1 and recs[0]["record_id"] == "agent.log"


def test_missing_store_inaccessible(tmp_path):
    store = _store(_cfg(tmp_path), "missing-export")
    ok, reason = store.probe()
    assert ok is False and "not found" in reason


def test_jsonl_delete_matching_on_copy(tmp_path):
    cfg = _cfg(tmp_path)
    store = _store(cfg, "memory-export")
    assert store.delete_matching({"mem-1"}) == 1
    assert [r["record_id"] for r in store.records()] == ["mem-2"]


def test_json_delete_matching(tmp_path):
    store = _store(_cfg(tmp_path), "vector-store")
    assert store.delete_matching({"vec-1"}) == 1
    data = json.loads(open(store.path).read())
    assert [r["id"] for r in data["records"]] == ["vec-2"]
