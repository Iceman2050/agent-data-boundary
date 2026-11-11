# agent-data-boundary

Cross-store personal-data lifecycle testing for AI agent systems.

An agent system scatters personal data across conversation databases, memory
exports, RAG/vector stores, and logs. When someone asks "delete my data" or
"how long do you keep this?", most teams answer from their config files and
hope. `agent-data-boundary` checks the files themselves: it inventories your
configured local stores, scans them for personal-data patterns, maps what was
declared against what was actually observed, validates retention against real
record ages, and runs a deletion test — search, delete on a working copy,
re-search — reporting per location:

- **VERIFIED** — the subject was found, deletion ran (on a copy), and the
  post-deletion re-query no longer finds them in that location.
- **UNVERIFIED** — the subject was found but deletion could not be performed
  or could not be re-checked for that location.
- **INACCESSIBLE** — the store could not be read at all.
- **NOT_FOUND** — the identifiers were not matched in that store at check
  time. That does not prove the data never existed there.

**The report never claims that "all copies are deleted."** It reports per
configured location only, and lists unconfigured locations as out of scope.

## Scope — read this first

- **Local files only.** V1 adapters read local files: SQLite databases,
  JSONL exports, JSON document stores, and directories of text files.
  There are **no network stores in V1** — no cloud APIs, no live databases,
  no external systems are contacted.
- **Deletion runs on copies.** `deletion-test` only deletes inside a copied
  working set, and only for stores your config explicitly marks
  `deletion_test_safe: true`. Your original store files are never modified
  by a deletion test.
- **Retention checks validate config vs local files.** They compare each
  store's declared retention policy against the ages of records in the local
  file. They do not reach into live external systems.
- **Pattern detection is not proof.** The detector is deterministic pattern
  matching: it has false positives and false negatives. "No findings with
  rules v1.0.0" means the patterns did not match — it never means a store is
  "PII-free". "Not found" does not mean "never existed", and a VERIFIED
  verdict for one configured location says nothing about any other system.
- This tool is an engineering testing aid. It is not a compliance
  certification, and using it does not by itself make any system compliant
  with any law.

## Install

Python 3.10+, standard library only — no dependencies.

```bash
pip install .
agent-data-boundary --config config.json inventory
```

Or run without installing: `python -m agent_data_boundary --config ... ...`
from the repo root.

## Config

A JSON file declaring your stores (paths resolve relative to the config):

```json
{
  "stores": [
    {
      "name": "conversations",
      "type": "sqlite",
      "path": "conversations.sqlite",
      "table": "conversations",
      "retention_days": 90,
      "retention_basis": "chat data kept 90 days per internal policy",
      "deletion_test_safe": true
    },
    {"name": "memory-export", "type": "jsonl", "path": "memory.jsonl",
     "retention_days": 90, "retention_basis": "exports kept 90 days",
     "deletion_test_safe": true},
    {"name": "vector-store", "type": "json", "path": "vectors.json",
     "retention_days": 90, "retention_basis": "RAG chunks kept 90 days",
     "deletion_test_safe": false},
    {"name": "logs", "type": "textdir", "path": "logs",
     "retention_days": null, "retention_basis": "",
     "deletion_test_safe": true}
  ]
}
```

Store types: `sqlite` (a SQLite DB file), `jsonl` (one JSON object per line),
`json` (a JSON list, or an object with a `records` list), `textdir` (a
directory of text files; each file is one record, deletion removes matching
lines on the copy).

## Commands

```bash
agent-data-boundary --config config.json inventory
agent-data-boundary --config config.json scan
agent-data-boundary --config config.json map
agent-data-boundary --config config.json retention-check
agent-data-boundary --config config.json deletion-test \
    --email someone@example.org --subject-id subj-123 --workdir ./work
```

- `inventory` — per store: ACCESSIBLE / INACCESSIBLE (with reason) + record count.
- `scan` — runs the PII detector over accessible stores; findings carry
  **masked excerpts only** (full sensitive values are never printed),
  anchored per (store, record id).
- `map` — data-flow map as namespaced nodes/edges JSON plus a Mermaid
  diagram, marking declared (config) vs observed (what a scan actually saw).
- `retention-check` — records older than the declared policy are flagged
  `RETENTION VIOLATION` with their age; records without a timestamp are
  counted separately, never silently passed.
- `deletion-test` — the search → delete-on-copy → re-search flow above.
  Its report entries are hash-chained evidence records, so the report can
  be re-verified for tampering.

## Demo fixtures

`python make_fixtures.py` builds a synthetic mini agent system under
`fixtures/` — a SQLite conversation DB, a JSONL memory export, a JSON
vector-store file, and a logs directory — containing obviously synthetic
data only (fake names, example.com addresses, 555 numbers, the standard
a standard Luhn-valid test card number). One synthetic subject is planted in some stores and
deliberately absent from one; one configured store path does not exist, so
a demo deletion-test run shows VERIFIED, UNVERIFIED, NOT_FOUND, and
INACCESSIBLE verdicts for real. See `BUILD-REPORT.md` for a captured run.

## Detector provenance

The PII detector rules were adopted from DisclosureGuard's `pii_scan` pack,
**rules version 1.0.0** (15 rules: secret shapes, Luhn-checked card numbers,
IBAN, US SSN, generic national ID, email, phone, private-range IP, with
example/fictional-value post-filters and masked excerpts). Rule IDs and the
version are preserved so the lineage is auditable; findings were re-anchored
from text offsets to (store, record) locations.

## How this differs from neighbouring tools

- **DisclosureGuard** checks ad creatives for disclosure compliance and runs
  a PII scan over a single text blob before publication. This repo tests the
  data lifecycle — inventory, retention, deletion — across many stores.
- **Agent Flight Recorder** manages retention and redaction inside its own
  action ledger. This repo verifies subject deletion across separately
  configured stores; it keeps no ledger of agent actions.

## License

MIT — see `LICENSE`.
