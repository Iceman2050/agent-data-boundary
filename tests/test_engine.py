import os

import make_fixtures
from agent_data_boundary import engine
from agent_data_boundary.config import load_config

IDS = [make_fixtures.SUBJECT_EMAIL, make_fixtures.SUBJECT_ID]


def _cfg(tmp_path):
    return load_config(make_fixtures.build(str(tmp_path)))


def test_inventory_accessibility(tmp_path):
    inv = engine.inventory(_cfg(tmp_path))
    by = {s["store"]: s for s in inv["stores"]}
    assert by["conversations"]["status"] == "ACCESSIBLE"
    assert by["conversations"]["records"] == 3
    assert by["missing-export"]["status"] == "INACCESSIBLE"


def test_scan_finds_planted_patterns(tmp_path):
    result = engine.scan(_cfg(tmp_path))
    rules = {f["rule_id"] for f in result["findings"]}
    assert "PII-PAY-001" in rules       # synthetic test card in sqlite body
    assert "PII-CONTACT-003" in rules   # private IP in jsonl ops note
    assert result["rules_version"] == "1.0.0"
    stores = {s["store"]: s for s in result["stores"]}
    assert stores["missing-export"]["status"] == "INACCESSIBLE"


def test_map_declared_vs_observed(tmp_path):
    m = engine.data_map(_cfg(tmp_path), engine.scan(_cfg(tmp_path)))
    node = next(n for n in m["nodes"] if n["id"] == "store:missing-export")
    assert node["declared"] is True and node["observed_accessible"] is False
    assert "flowchart" in m["mermaid"]
    assert any(e["to"] == "store:conversations" for e in m["edges"])


def test_retention_violation_flagged(tmp_path):
    result = engine.retention_check(_cfg(tmp_path))
    conv = next(r for r in result["results"] if r["store"] == "conversations")
    assert len(conv["violations"]) == 1
    v = conv["violations"][0]
    assert v["verdict"] == "RETENTION VIOLATION" and v["age_days"] > 90
    missing = next(r for r in result["results"] if r["store"] == "missing-export")
    assert missing["status"] == "INACCESSIBLE"


def test_deletion_test_three_states(tmp_path):
    report = engine.deletion_test(_cfg(tmp_path), IDS,
                                  workdir=str(tmp_path / "work"))
    by = {r["store"]: r for r in report["results"]}
    assert by["conversations"]["verdict"] == "VERIFIED"
    assert by["logs"]["verdict"] == "VERIFIED"
    assert by["vector-store"]["verdict"] == "UNVERIFIED"   # not deletion_test_safe
    assert by["memory-export"]["verdict"] == "NOT_FOUND"  # subject never planted
    assert by["missing-export"]["verdict"] == "INACCESSIBLE"
    assert report["evidence_chain_valid"] is True
    assert "not configured are out of scope" in report["scope_note"]
    # The report never makes a global "everything is deleted" claim.
    assert "all copies anywhere are deleted" in report["scope_note"].lower()
    assert "never claims that all copies" not in report["scope_note"]


def test_deletion_test_never_touches_originals(tmp_path):
    cfg = _cfg(tmp_path)
    engine.deletion_test(cfg, IDS, workdir=str(tmp_path / "work"))
    inv = engine.inventory(cfg)
    conv = next(s for s in inv["stores"] if s["store"] == "conversations")
    assert conv["records"] == 3  # original untouched; deletion ran on a copy
    log_text = open(os.path.join(str(tmp_path), "logs", "agent.log")).read()
    assert make_fixtures.SUBJECT_EMAIL in log_text


def test_deletion_test_requires_identifier(tmp_path):
    try:
        engine.deletion_test(_cfg(tmp_path), [])
        raise AssertionError("should have raised")
    except ValueError:
        pass
