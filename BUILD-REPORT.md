# Build Report — agent-data-boundary v0.1.0

Date: 2026-11-11 · Build location: ~/workspace/github-repos-build/agent-data-boundary/

## Reuse evidence (overlap gate: PROCEED with reuse)

- Detector rules ported from DisclosureGuard's `app/pii_scan.py`,
  **rules version 1.0.0 — all 15 rules** (PII-SECRET-001..008, PII-PAY-001/002,
  PII-ID-001/002, PII-CONTACT-001..003), including Luhn validation, the
  example/fictional post-filters, private-range IP check, masked excerpts,
  and the "no findings with rules vX — never PII-free" verdict discipline.
  Rule IDs and version preserved; findings re-anchored from text offsets to
  (store, record_id). Provenance credited in `detector.py` and the README.
- Faithful-port note: the source pack's repeated-digit post-filter rejects
  the classic 4111... test card (only 2 distinct digits), so fixtures use
  the Luhn-valid test card 4012888888881881 instead. This is the original
  pack's behaviour, kept deliberately.
- Pattern reuse: namespaced nodes/edges + Mermaid (agent-skill-sbom idiom),
  hash-chained evidence records (DisclosureGuard certificate idiom,
  `evidence.py`), snapshot->diff mental model for post-deletion re-query.

## Suite

`python -m pytest -q` -> **28 passed** (detector 11, stores 7, engine 7, CLI 3).
Covers every rule class incl. Luhn pass/fail, masking never leaking full
values, per-adapter reads/deletes, inventory accessibility, retention
violations, deletion-test end-to-end (VERIFIED / UNVERIFIED / NOT_FOUND /
INACCESSIBLE), originals-untouched proof, and CLI smoke tests.

## Real fixture run (unedited transcript)

The demo deletion test ran against COPIES under the given --workdir; the
fixture originals were verified unchanged afterwards (suite test
`test_deletion_test_never_touches_originals` asserts the same).

```text
$ agent-data-boundary --config fixtures/config.json inventory
{
  "generated_at": "2026-11-11T15:39:32.039980+00:00",
  "stores": [
    {
      "store": "conversations",
      "type": "sqlite",
      "path": "/home/hatch/workspace/github-repos-build/agent-data-boundary/fixtures/conversations.sqlite",
      "status": "ACCESSIBLE",
      "reason": "ok",
      "records": 3,
      "retention_days": 90,
      "deletion_test_safe": true
    },
    {
      "store": "memory-export",
      "type": "jsonl",
      "path": "/home/hatch/workspace/github-repos-build/agent-data-boundary/fixtures/memory.jsonl",
      "status": "ACCESSIBLE",
      "reason": "ok",
      "records": 2,
      "retention_days": 90,
      "deletion_test_safe": true
    },
    {
      "store": "vector-store",
      "type": "json",
      "path": "/home/hatch/workspace/github-repos-build/agent-data-boundary/fixtures/vectors.json",
      "status": "ACCESSIBLE",
      "reason": "ok",
      "records": 2,
      "retention_days": 90,
      "deletion_test_safe": false
    },
    {
      "store": "logs",
      "type": "textdir",
      "path": "/home/hatch/workspace/github-repos-build/agent-data-boundary/fixtures/logs",
      "status": "ACCESSIBLE",
      "reason": "ok",
      "records": 1,
      "retention_days": null,
      "deletion_test_safe": true
    },
    {
      "store": "missing-export",
      "type": "jsonl",
      "path": "/home/hatch/workspace/github-repos-build/agent-data-boundary/fixtures/does-not-exist.jsonl",
      "status": "INACCESSIBLE",
      "reason": "file not found: /home/hatch/workspace/github-repos-build/agent-data-boundary/fixtures/does-not-exist.jsonl",
      "records": null,
      "retention_days": 90,
      "deletion_test_safe": true
    }
  ]
}

$ agent-data-boundary --config fixtures/config.json scan
{
  "generated_at": "2026-11-11T15:39:32.108675+00:00",
  "rules_version": "1.0.0",
  "verdict": "2 finding(s) with rules v1.0.0",
  "note": "Pattern detection has false positives and false negatives. A no-findings result is never a claim that a store is PII-free.",
  "stores": [
    {
      "store": "conversations",
      "status": "ACCESSIBLE",
      "records_scanned": 3
    },
    {
      "store": "memory-export",
      "status": "ACCESSIBLE",
      "records_scanned": 2
    },
    {
      "store": "vector-store",
      "status": "ACCESSIBLE",
      "records_scanned": 2
    },
    {
      "store": "logs",
      "status": "ACCESSIBLE",
      "records_scanned": 1
    },
    {
      "store": "missing-export",
      "status": "INACCESSIBLE",
      "reason": "file not found: /home/hatch/workspace/github-repos-build/agent-data-boundary/fixtures/does-not-exist.jsonl"
    }
  ],
  "findings": [
    {
      "store": "conversations",
      "record_id": "conversations:1",
      "rule_id": "PII-PAY-001",
      "category": "Credit card",
      "severity": "critical",
      "excerpt": "40*************1 ",
      "suggestion": "Remove the card number \u2014 never store full PANs.",
      "rules_version": "1.0.0"
    },
    {
      "store": "memory-export",
      "record_id": "mem-2",
      "rule_id": "PII-CONTACT-003",
      "category": "IP address",
      "severity": "high",
      "excerpt": "19********20",
      "suggestion": "Remove internal IP addresses from stored records.",
      "rules_version": "1.0.0"
    }
  ]
}

$ agent-data-boundary --config fixtures/config.json retention-check
{
  "generated_at": "2026-11-11T15:39:32.168251+00:00",
  "results": [
    {
      "store": "conversations",
      "retention_days": 90,
      "retention_basis": "demo policy: chat data kept 90 days",
      "violations": [
        {
          "record_id": "conversations:3",
          "timestamp": "2025-10-07T15:39:31.833594+00:00",
          "age_days": 400,
          "policy_days": 90,
          "verdict": "RETENTION VIOLATION"
        }
      ],
      "records_checked": 3,
      "records_without_timestamp": 0,
      "status": "ACCESSIBLE"
    },
    {
      "store": "memory-export",
      "retention_days": 90,
      "retention_basis": "demo policy: memory exports kept 90 days",
      "violations": [],
      "records_checked": 2,
      "records_without_timestamp": 0,
      "status": "ACCESSIBLE"
    },
    {
      "store": "vector-store",
      "retention_days": 90,
      "retention_basis": "demo policy: RAG chunks kept 90 days",
      "violations": [],
      "records_checked": 2,
      "records_without_timestamp": 0,
      "status": "ACCESSIBLE"
    },
    {
      "store": "logs",
      "retention_days": null,
      "retention_basis": "no declared retention in demo",
      "violations": [],
      "records_checked": 0,
      "records_without_timestamp": 0,
      "status": "ACCESSIBLE",
      "note": "no retention policy declared for this store \u2014 nothing to validate against"
    },
    {
      "store": "missing-export",
      "retention_days": 90,
      "retention_basis": "demo policy",
      "violations": [],
      "records_checked": 0,
      "records_without_timestamp": 0,
      "status": "INACCESSIBLE",
      "reason": "file not found: /home/hatch/workspace/github-repos-build/agent-data-boundary/fixtures/does-not-exist.jsonl"
    }
  ],
  "note": "This validates the declared config policy against local files only. It does not reach into live external systems."
}

$ agent-data-boundary --config fixtures/config.json deletion-test --email testa@example.com --subject-id subj-test-a --workdir /tmp/adb-demo-work
{
  "generated_at": "2026-11-11T15:39:32.234870+00:00",
  "subject_identifiers_masked": [
    "te***",
    "su***"
  ],
  "working_copy_dir": "/tmp/adb-demo-work",
  "results": [
    {
      "store": "conversations",
      "type": "sqlite",
      "verdict": "VERIFIED",
      "found_record_ids": [
        "conversations:1"
      ],
      "detail": "found before deletion, not found on re-query of the working copy after deletion. The original store file was not modified.",
      "prev_hash": "GENESIS",
      "hash": "12ec6695ace9bfbb8c734c3681a55e3458d0560e81b4d755e37621d90152d546"
    },
    {
      "store": "memory-export",
      "type": "jsonl",
      "verdict": "NOT_FOUND",
      "detail": "identifiers not matched in this store at check time (does not prove they never existed here)",
      "prev_hash": "12ec6695ace9bfbb8c734c3681a55e3458d0560e81b4d755e37621d90152d546",
      "hash": "bf82a927de43c59d77febec89f4ecb3f55f9e5cee5b5ddaa660826aa1f4442a2"
    },
    {
      "store": "vector-store",
      "type": "json",
      "verdict": "UNVERIFIED",
      "found_record_ids": [
        "vec-1"
      ],
      "detail": "records found, but store is not marked deletion_test_safe \u2014 deletion not attempted",
      "prev_hash": "bf82a927de43c59d77febec89f4ecb3f55f9e5cee5b5ddaa660826aa1f4442a2",
      "hash": "9fa65353505d28e055335ee6d6fd1957e38b026b033dc6671ec8be6dbc1e05aa"
    },
    {
      "store": "logs",
      "type": "textdir",
      "verdict": "VERIFIED",
      "found_record_ids": [
        "agent.log"
      ],
      "detail": "found before deletion, not found on re-query of the working copy after deletion. The original store file was not modified.",
      "prev_hash": "9fa65353505d28e055335ee6d6fd1957e38b026b033dc6671ec8be6dbc1e05aa",
      "hash": "035ea2b75f7b8512be5869207ae19990509ce668a8076832bd0bcafc0ab8fb58"
    },
    {
      "store": "missing-export",
      "type": "jsonl",
      "verdict": "INACCESSIBLE",
      "detail": "store could not be read: file not found: /home/hatch/workspace/github-repos-build/agent-data-boundary/fixtures/does-not-exist.jsonl",
      "prev_hash": "035ea2b75f7b8512be5869207ae19990509ce668a8076832bd0bcafc0ab8fb58",
      "hash": "be52c37673175596752679c1e957f8996a5f8f20bd2629145d23ef348433c0b0"
    }
  ],
  "evidence_chain_valid": true,
  "scope_note": "Scope: only the stores declared in the config were checked. Locations not configured are out of scope and are NOT covered by this report. 'Not found' means the identifiers were not matched in that store at check time \u2014 it does not prove the data never existed there, and no result here claims that all copies anywhere are deleted."
}

```
