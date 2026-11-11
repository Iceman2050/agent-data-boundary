"""Core operations: inventory, scan, map, retention-check, deletion-test."""
import os
import shutil
import tempfile
from datetime import datetime, timezone

from . import detector, evidence
from .stores import open_store, TextDirStore

HONESTY_NOTE = (
    "Scope: only the stores declared in the config were checked. Locations "
    "not configured are out of scope and are NOT covered by this report. "
    "'Not found' means the identifiers were not matched in that store at "
    "check time — it does not prove the data never existed there, and no "
    "result here claims that all copies anywhere are deleted."
)


def _now():
    return datetime.now(timezone.utc)


def inventory(config):
    out = []
    for cfg in config["stores"]:
        store = open_store(cfg)
        ok, reason = store.probe()
        count = None
        if ok:
            try:
                count = len(store.records())
            except Exception as exc:
                ok, reason = False, "read failed: %s" % exc
        out.append({"store": cfg["name"], "type": cfg["type"], "path": cfg["path"],
                    "status": "ACCESSIBLE" if ok else "INACCESSIBLE",
                    "reason": reason, "records": count,
                    "retention_days": cfg.get("retention_days"),
                    "deletion_test_safe": bool(cfg.get("deletion_test_safe"))})
    return {"generated_at": _now().isoformat(), "stores": out}


def scan(config):
    findings, scanned = [], []
    for cfg in config["stores"]:
        store = open_store(cfg)
        ok, reason = store.probe()
        if not ok:
            scanned.append({"store": cfg["name"], "status": "INACCESSIBLE",
                            "reason": reason})
            continue
        recs = store.records()
        for r in recs:
            findings.extend(detector.scan_record(cfg["name"], r["record_id"], r["text"]))
        scanned.append({"store": cfg["name"], "status": "ACCESSIBLE",
                        "records_scanned": len(recs)})
    return {"generated_at": _now().isoformat(),
            "rules_version": detector.PII_RULES_VERSION,
            "verdict": ("no findings with rules v%s in the accessible stores"
                        % detector.PII_RULES_VERSION) if not findings else
                       "%d finding(s) with rules v%s" % (len(findings),
                                                          detector.PII_RULES_VERSION),
            "note": "Pattern detection has false positives and false negatives. "
                    "A no-findings result is never a claim that a store is PII-free.",
            "stores": scanned, "findings": findings}


def data_map(config, scan_result=None):
    """Namespaced nodes/edges + Mermaid, declared vs observed (SBOM idiom)."""
    nodes, edges = {}, []
    nodes["agent:system"] = {"id": "agent:system", "kind": "agent"}
    observed = {}
    if scan_result:
        for f in scan_result["findings"]:
            observed[f["store"]] = observed.get(f["store"], 0) + 1
    for cfg in config["stores"]:
        sid = "store:%s" % cfg["name"]
        store = open_store(cfg)
        ok, _ = store.probe()
        nodes[sid] = {"id": sid, "kind": "store", "type": cfg["type"],
                      "declared": True, "observed_accessible": ok,
                      "retention_days": cfg.get("retention_days"),
                      "pii_findings_observed": observed.get(cfg["name"], 0)}
        edges.append({"from": "agent:system", "to": sid,
                      "label": "personal data (declared in config)"})
    lines = ["flowchart LR", "    agent_system[\"agent:system\"]"]
    for cfg in config["stores"]:
        lines.append("    %s[\"store:%s (%s)\"]" % (
            cfg["name"].replace("-", "_"), cfg["name"], cfg["type"]))
        lines.append("    agent_system -->|personal data (declared)| %s"
                     % cfg["name"].replace("-", "_"))
    return {"generated_at": _now().isoformat(),
            "nodes": list(nodes.values()), "edges": edges,
            "mermaid": "\n".join(lines),
            "note": "Edges are declared in config; node fields mark what a "
                    "scan actually observed. Declared is not the same as verified."}


def _parse_ts(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def retention_check(config, now=None):
    now = now or _now()
    results = []
    for cfg in config["stores"]:
        store = open_store(cfg)
        ok, reason = store.probe()
        entry = {"store": cfg["name"], "retention_days": cfg.get("retention_days"),
                 "retention_basis": cfg.get("retention_basis", ""),
                 "violations": [], "records_checked": 0, "records_without_timestamp": 0}
        if not ok:
            entry["status"] = "INACCESSIBLE"
            entry["reason"] = reason
            results.append(entry)
            continue
        entry["status"] = "ACCESSIBLE"
        if cfg.get("retention_days") is None:
            entry["note"] = "no retention policy declared for this store — nothing to validate against"
            results.append(entry)
            continue
        for r in store.records():
            entry["records_checked"] += 1
            ts = _parse_ts(r["timestamp"])
            if ts is None:
                entry["records_without_timestamp"] += 1
                continue
            age = (now - ts).days
            if age > cfg["retention_days"]:
                entry["violations"].append({
                    "record_id": r["record_id"], "timestamp": r["timestamp"],
                    "age_days": age, "policy_days": cfg["retention_days"],
                    "verdict": "RETENTION VIOLATION"})
        results.append(entry)
    return {"generated_at": now.isoformat(), "results": results,
            "note": "This validates the declared config policy against local "
                    "files only. It does not reach into live external systems."}


def _search(store, identifiers):
    return [r for r in store.records()
            if any(i in r["text"] for i in identifiers)]


def _copy_store(cfg, workdir):
    """Copy a store into the working set; deletion only ever touches copies."""
    dest_dir = os.path.join(workdir, cfg["name"])
    os.makedirs(dest_dir, exist_ok=True)
    if cfg["type"] == "textdir":
        dest = os.path.join(dest_dir, "files")
        shutil.copytree(cfg["path"], dest)
    else:
        dest = os.path.join(dest_dir, os.path.basename(cfg["path"]))
        shutil.copy2(cfg["path"], dest)
    new_cfg = dict(cfg, path=dest)
    return new_cfg


def deletion_test(config, identifiers, workdir=None):
    """Search → delete on COPIES of safe stores only → re-search → tri-state report."""
    if not identifiers:
        raise ValueError("at least one subject identifier is required")
    workdir = workdir or tempfile.mkdtemp(prefix="adb-deletion-test-")
    entries = []
    for cfg in config["stores"]:
        store = open_store(cfg)
        ok, reason = store.probe()
        base = {"store": cfg["name"], "type": cfg["type"]}
        if not ok:
            entries.append({**base, "verdict": "INACCESSIBLE",
                            "detail": "store could not be read: %s" % reason})
            continue
        before = _search(store, identifiers)
        if not before:
            entries.append({**base, "verdict": "NOT_FOUND",
                            "detail": "identifiers not matched in this store at "
                                      "check time (does not prove they never existed here)"})
            continue
        found_ids = [r["record_id"] for r in before]
        if not cfg.get("deletion_test_safe"):
            entries.append({**base, "verdict": "UNVERIFIED",
                            "found_record_ids": found_ids,
                            "detail": "records found, but store is not marked "
                                      "deletion_test_safe — deletion not attempted"})
            continue
        copy_cfg = _copy_store(cfg, workdir)
        copy_store = open_store(copy_cfg)
        try:
            if isinstance(copy_store, TextDirStore):
                copy_store.delete_lines_containing(identifiers)
            else:
                copy_store.delete_matching(set(found_ids))
        except Exception as exc:
            entries.append({**base, "verdict": "UNVERIFIED",
                            "found_record_ids": found_ids,
                            "detail": "deletion on the working copy failed: %s" % exc})
            continue
        after = _search(copy_store, identifiers)
        if after:
            entries.append({**base, "verdict": "UNVERIFIED",
                            "found_record_ids": found_ids,
                            "detail": "records still matched after deletion on the "
                                      "working copy (record ids: %s)"
                                      % [r["record_id"] for r in after]})
        else:
            entries.append({**base, "verdict": "VERIFIED",
                            "found_record_ids": found_ids,
                            "detail": "found before deletion, not found on re-query "
                                      "of the working copy after deletion. The "
                                      "original store file was not modified."})
    evidence.chain(entries)
    return {"generated_at": _now().isoformat(),
            "subject_identifiers_masked": [i[:2] + "***" if len(i) > 2 else "***"
                                           for i in identifiers],
            "working_copy_dir": workdir,
            "results": entries,
            "evidence_chain_valid": evidence.verify_chain(entries),
            "scope_note": HONESTY_NOTE}
