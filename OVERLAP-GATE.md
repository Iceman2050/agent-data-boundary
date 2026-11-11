# Overlap Gate — agent-data-boundary vs the fleet's skill/plugin supply-chain tooling

Date: 2026-11-11 · Inspection only (nothing built, nothing uploaded)

## Verdict: **PROCEED with reuse**

The domain is materially distinct. The existing tools inventory **code artifacts an
agent loads** (skills, plugins, MCP configs) and prove where those artifacts came from
and whether they changed. `agent-data-boundary` inventories **personal data an agent
system holds** (memory exports, RAG/vector stores, logs, databases) and tests what
happens to a data subject's records across that data's lifecycle — retention and,
above all, whether a deletion actually took effect in every configured location.
No existing fleet asset does subject-key search, cross-store deletion orchestration,
or post-deletion retrieval testing in substance, so there is no fold-in candidate.

Reuse is real but bounded: one detector rule pack, and several evidence/inventory
*patterns* (snapshot→diff, hash-chained evidence records, honest "not found ≠ clean"
verdict wording). The core of the proposal — configurable data-store inventory,
data-flow mapping for personal data, retention validation against stores, deletion
test orchestration, post-deletion re-queries, and the per-location
VERIFIED / UNVERIFIED / INACCESSIBLE report — is new build.

---

## What was actually read

### 1. agent-shield (Iceman2050/agent-shield, public, v0.1.0)

- Live GitHub README, fetched 2026-11-11. Its own description: "Security scanner for
  AI agent artifacts — skills, MCP configs, plugins. Agent SBOM inventory, risky-code
  and suspicious-instruction detection, version locking."
- It states it "consolidates two earlier Ingenious AI tools — agent-skill-sbom and
  plugin-provenance-verifier — into one scanner."
- What it does, per the README: inventories every skill, plugin and MCP config in a
  directory and emits an **Agent SBOM (ACBOM)** — per-file sha256, executable
  components, declared vs. observed capabilities, dependencies; detects deterministic
  risks in the *code* (hardcoded secrets, shell execution, `eval`/`exec`,
  credential-file access, network egress, `curl | sh`, unpinned dependencies, MCP
  servers launching shells or carrying literal secrets in `env`); flags suspicious
  instructions in `SKILL.md` text; writes `agent-shield.lock.json` and diffs installed
  artifacts against the lock. Output formats: console / JSON / SARIF 2.1.0; exit 1 on
  a critical finding or on lock diff.
- Honest limitations it declares: static analysis only, never executes what it scans,
  local only, no network access. Nothing in the README concerns personal data,
  data subjects, retention, or deletion.
- Local-source note: there is **no** `agent-shield` tree under
  `~/workspace/github-repos-build/` as of 2026-11-11 (that directory holds
  agent-bridge, agent-proof, agent-recovery-lab, repo-mind, sop-contract,
  trace2contract). Evidence for agent-shield is therefore its live GitHub README;
  evidence for its two predecessors is both local source and GitHub (below).

### 2. agent-skill-sbom (Iceman2050/agent-skill-sbom)

- Live GitHub README, fetched 2026-11-11: "SBOM for agent skills — dependency graph
  builder." It scans a directory of skills (each a folder with a `SKILL.md`) and
  builds a directed dependency graph **skill → package → network** from
  `requirements.txt`, `package.json`, `pip install` / `npm install` lines in docs,
  install scripts, and URLs in docs. Flags: INSTALL_SCRIPT, UNPINNED_DEP,
  TRANSITIVE_CHAIN, SHARED_PACKAGE.
- JSON output shape (from the README's schema section): top-level
  `tool` / `version` / `root` / `skills[]`; a `nodes` map with namespaced ids
  (`skill:…`, `pkg:…`, `url:…`); an `edges` list (`from`, `to`, `label`); findings as
  `{severity, code, message}`; field names `name` / `version` / `findings` kept
  compatible with its sibling scanner so outputs can be joined. Also emits a Mermaid
  flowchart of the graph.
- Its own non-claims: "Not a vulnerability scanner. It maps provenance and dependency
  structure… No network access. Everything is derived from files on disk."
  The graph's nodes are packages and URLs — not data stores, and it carries no
  personal-data, retention, or deletion concept.

### 3. plugin-provenance-verifier (local source + GitHub)

- Local source read: `~/workspace/unicorn-wave12-plugin-provenance-verifier/`
  (`provenance/scanner.py`, `snapshot.py`, `differ.py`, `cli.py`; README identical in
  substance to Iceman2050/plugin-provenance-verifier on GitHub, fetched 2026-11-11).
- `scanner.py::scan_plugins` walks a plugins directory, parses each plugin's manifest
  (`plugin.json` / `manifest.json`), and returns a record per plugin:
  `plugin_id, name, version, origin` (the manifest's *declared* `source`, labelled
  "NOT independently verified"), `official, auto_update, mcp_servers`,
  `files` (relative path → sha256, via a chunked `hash_file`), `warnings`.
- `snapshot.py` persists that scan as a versioned JSON snapshot
  (`format_version: 1`, `taken_at`, `plugins_dir`, per-plugin subset of fields).
- `differ.py::diff_snapshot` compares a fresh scan to the snapshot and emits findings
  as `{plugin, kind, severity, detail}` — VERSION_DRIFT, NEW_MCP_SERVER, FILE_CHANGED /
  FILE_ADDED / FILE_REMOVED, PLUGIN_ADDED / PLUGIN_REMOVED, SIDELOADED_ORIGIN.
- README non-claims: origin is declared, not verified; it does not audit what MCP
  servers do at runtime; read-only, does not block updates or uninstall anything.
  This is install-time provenance and drift of *code bundles* — no data content is
  ever read for personal information, and "removed" means a plugin directory
  disappeared, not that a person's records were erased.

### 4. DisclosureGuard — actual scope (platforms/disclosure-guard)

- README read: AI **disclosure compliance for ad creatives, videos and images** —
  reads declared/embedded provenance (C2PA/JUMBF manifests, XMP, EXIF, frame-level
  video scans) and checks assets against versioned jurisdiction rules (EU AI Act
  Art. 50, US/Google Ads synthetic-content disclosure, China's AI-labeling measures).
  "It is not an AI detector." Adjacent modules in the same README: an
  Agentic-Obligations Readiness Mapper (grades a *declared* agent-autonomy config
  against Articles 9/14/11/12) and an Agent-Liability Jurisdiction Tracker.
  Neither touches a customer's data stores.
- The one genuine personal-data feature, shipped 2026-10-13 per `KILLER-FEATURES.md`
  and verified in source `app/pii_scan.py`: a **Pre-Publish PII Scan** — a
  deterministic pattern engine run over a single text blob (AI-generated ad copy,
  capped at 20,000 chars in `app/main.py`) before publication, plus hash-chained
  **Sanitization Certificates** attesting that the scan ran.
  `pii_scan.py` details: `PII_RULES_VERSION = "1.0.0"`; 15 rules — API-key/secret
  shapes (AWS, GitHub, Anthropic, OpenAI, Stripe, Slack tokens, private-key blocks,
  generic credential assignments), credit card (with Luhn validation), IBAN, US SSN,
  generic national-ID patterns, email, phone, private-range IP; post-filters reject
  example/fictional values; `scan_text()` returns findings as
  `{rule_id, category, severity, excerpt (masked), start, end, suggestion}`; the
  module's hard rule is that a clean result is "no findings with rules vX", never
  "PII-free".
- In `app/agentic_obligations.py` (line ~326) a "documented retention policy" appears
  only as one criterion in grading a customer's *declaration* — no store is inspected.
- DisclosureGuard has **no** data-subject search, **no** data-store connectors,
  **no** retention validation against stored records, and **no** deletion or
  post-deletion verification of any kind. Its PII work is pre-publish hygiene for
  marketing copy inside a hosted compliance SaaS — a different surface, a different
  input shape (one text blob), and a different question ("does this copy leak PII?")
  from agent-data-boundary's ("where does this person's data live, and is it gone?").

### 5. Fleet-wide platform sweep (~/workspace/platforms)

Method: searched all platform source/docs for `deletion verification`,
`post-deletion`, `retention policy`, `deletion request`, and for PII-scanning code.
Only three platforms produced hits, and only one PII-scanning module exists:

- **Agent Flight Recorder** (`platforms/agent-flight-recorder`) — the closest
  neighbour, and still a different domain:
  - `app/capture_policy.py`: capture-time, policy-driven **redaction** of agent
    action payloads before they are hashed into AFR's own ledger. A detector
    registry (email, phone, IBAN, SSN, Luhn-checked card, OpenAI/AWS/GitHub/Slack/
    Google API keys, JWT, plus per-workspace custom regex) and three capture modes
    (hash-only default, redacted-full, full-with-warning). Every redaction mints a
    receipt `{field_path, policy_version, detector_id, redacted_value_sha256}` —
    the receipt never contains the value. This prevents sensitive data entering
    *one product's own log*; it does not find personal data across a customer's
    systems.
  - `app/ultra.py`: **retention + shredding for AFR's own ledger only** —
    `RETENTION_TIERS` (6/12/36/84 months or indefinite), `set_retention`,
    `expired_seqs` (age-based, by ledger sequence number), legal holds that exempt
    ranges, `run_retention_pass`, and `shred_range`, which tombstones payloads in
    place ("[shredded under …]"), keeps record hashes / payload commitments / chain
    links so the chain still verifies, and mints a signed Shred Receipt. Two facts
    matter for this gate: (a) shredding is triggered by *record age*, never by a
    data-subject request, and no subject key is ever searched; (b) before shredding,
    `build_archival_pack` stores the **full records** in an `archives` table whose
    hash the receipt certifies — i.e. AFR's design deliberately retains proof
    artifacts, the opposite of verifying that all copies of a person's data are
    gone. It is a single-store, self-referential mechanism, not cross-store
    deletion verification.
- **TermsWatch** (`platforms/terms-watch`) — `app/exposure.py` flags a *vendor's*
  long stated retention as a risk finding, and `app/watcher.py` holds an
  ask-the-vendor template ("How do I request deletion of my data, and what are the
  exceptions?"). It reads third-party terms text; it performs no scanning,
  retention validation, or deletion testing.
- **DisclosureGuard** — the one checklist line noted in §4. No other platform
  produced a hit. BoundaryVault and the remaining platforms contain no PII
  detection, personal-data inventory, retention, or deletion-verification code.

Related pattern precedent (not a platform): `unicorn-wave13-mcp-sbom-guard`
(`mcp_sbom_guard.py`) verifies declared MCP component versions against a static CVE
feed with verdicts VULNERABLE / REVIEW / OK, where OK is explicitly glossed
"not in bundled feed — not a clean bill of health". Supply-chain again, but its
honest-verdict wording is the fleet's existing idiom for the kind of claim
discipline agent-data-boundary's report needs.

---

## Per-component evidence table

| Proposed component | Exists where (evidence) | Reusable how — or why not |
|---|---|---|
| Inventory data model | agent-shield ACBOM (per-artifact: per-file sha256, executable components, declared vs observed capabilities, dependencies — GitHub README); agent-skill-sbom JSON (`tool`/`version`/`root`, namespaced node ids, `edges`, findings `{severity, code, message}`); plugin-provenance-verifier record + snapshot (`format_version: 1`) | **Pattern reuse only.** The namespaced-node/edge JSON conventions, the declared-vs-observed distinction, and the versioned-snapshot format are sound shapes to mirror for a data-store inventory. The schemas themselves are **not** reusable: their entities are skills/packages/plugins/files, with no field for store type, subject keys, data categories, retention, or access state. The data-store inventory model is new build. |
| Local scanning engine | plugin-provenance-verifier `provenance/scanner.py` (`os.walk` inventory, chunked sha256 `hash_file`, manifest parsing); agent-shield (stdlib-only, local, never executes scanned artifacts, no network — README limitations) | **Partial reuse.** The walk + hash + never-execute discipline transfers directly to scanning authorized local memory *exports* (files on disk). It does not transfer to the rest of the scope: readers/queries for databases, vector/RAG indexes, log stores, and remote/configured stores, plus subject-key matching inside structured records, are new build. |
| Sensitive-information detection | DisclosureGuard `app/pii_scan.py` (15 versioned rules, Luhn/example post-filters, masked excerpts, `scan_text()` finding shape); AFR `app/capture_policy.py` detector registry (overlapping categories + custom regex) | **Genuinely reusable — the strongest reuse in this gate.** Adopt one canonical rule pack (DisclosureGuard's: it is versioned `1.0.0`, returns position + masked excerpt + redaction suggestion, and carries the "no findings ≠ PII-free" rule) as the detector core for text-bearing stores/exports. Note the fleet already maintains two overlapping packs; agent-data-boundary should consume one, not grow a third. Adaptation still needed: findings must be re-anchored from (start, end) in one text blob to (store, record/locator, subject match) across stores. |
| Data-flow mapping | agent-skill-sbom dependency graph (skill → package → network, Mermaid + nodes/edges JSON) | **Rendering/graph pattern only.** Namespaced nodes, labelled edges, and Mermaid output are reusable as an output technique. The semantics are new: agent-skill-sbom's edges are package dependencies extracted from manifests/docs; agent-data-boundary's edges are personal-data flows derived from declared configurations + instrumented events. Event ingestion and the flow model are new build. |
| Retention-policy validation | AFR `app/ultra.py` (`RETENTION_TIERS`, `set_retention`, `expired_seqs`, legal holds, `run_retention_pass`) | **Design reference, not code reuse.** AFR proves the fleet's idiom for tiered retention, age expiry, and hold exemptions — inside its own ledger, enforced by AFR itself. agent-data-boundary must *validate* third-party stores' declared retention against what is actually stored there (oldest/subject records vs policy), a read-only external test that does not exist anywhere in the fleet. New build. |
| Deletion-request test orchestration | Nothing. Nearest mechanism: AFR `shred_range` | **Not reusable, and not equivalent.** `shred_range` deletes (tombstones) one product's own rows by age/sequence range, keeps hashes and commitments, and first archives the full records into an `archives` table. agent-data-boundary orchestrates a *subject's* deletion request across configured external stores and records each store's response — no subject concept, no cross-store orchestration, and no request/response tracking exists in any asset read. New build. |
| Post-deletion retrieval tests | Nothing. Nearest patterns: plugin-provenance-verifier snapshot→diff; AFR post-shred `chain.verify_chain` re-check | **New build, on a reusable pattern.** Re-scanning after an event and diffing against a baseline is exactly the provenance verifier's snapshot→diff shape, and AFR re-verifies its chain after shredding — both are good templates for "baseline scan → deletion → re-query → compare". But no tool re-queries configured stores for a subject's records after deletion; the retrieval probes per store type are new build. |
| Report with per-location VERIFIED / UNVERIFIED / INACCESSIBLE | No equivalent exists. Partial precedents: DisclosureGuard hash-chained Sanitization Certificates (`certificate_hash` over prev_hash + content hash + rules version + finding count) and AFR signed Shred Receipts + redaction receipts (hash-only evidence, never the value); honest-verdict idiom in DisclosureGuard ("no findings with rules vX") and mcp-sbom-guard (OK = "not in the bundled feed") | **Evidence-record pattern reusable; the report itself is new.** Hash-chained, hash-only evidence records and the fleet's refusal to equate "not found" with "clean" should be carried over as the report's integrity layer. The tri-state per-location verdict — in particular INACCESSIBLE as a first-class outcome and the rule that one store's no-match never becomes a global "deleted" claim — has no precedent implementation and is new build. |
| Configurable data-store inventory (store registry: type, location, access, retention) | Nothing. Existing inventories are fixed-shape directory scans (a plugins dir, a skills dir) with hard-coded manifest assumptions | **Not reusable.** No asset read has a user-configured registry of heterogeneous stores. New build — this is the proposal's foundation, and its absence elsewhere is the clearest sign the domain is unserved. |

---

## Why this is not an EXPANSION / FOLD-IN

A fold-in would require an existing asset that already, in substance, (a) inventories
where a subject's personal data lives across multiple stores, (b) tests retention
against those stores, or (c) verifies deletion by re-querying them. None does:

- agent-shield / agent-skill-sbom / plugin-provenance-verifier never read data
  content for personal information at all; their "inventory" is of code artifacts,
  their "verification" is of declared origin and file drift.
- DisclosureGuard's PII scan is real but bounded to pre-publish marketing copy in a
  hosted SaaS; it has no stores, no subjects, no deletion surface. Folding a local,
  open-source, cross-store deletion-testing CLI into it would change both products'
  shapes to neither's benefit. Its detector pack is the correct level of reuse.
- Agent Flight Recorder's retention/shred machinery is the nearest in *vocabulary*
  only: it manages the retention of its own append-only ledger by age, retains an
  archival pack of the very records it shreds, and never searches for a person.
  It is a logging product feature, not a data-lifecycle testing tool, and its
  design goal (proof that history attests) is in tension with erasure verification.

## Bottom line for the build (when separately approved)

- **Reuse:** DisclosureGuard's `pii_scan.py` rule pack + finding shape (one canonical
  detector — do not create a third fleet PII pack); snapshot→diff architecture from
  plugin-provenance-verifier; namespaced nodes/edges + Mermaid conventions from
  agent-skill-sbom; hash-chained / hash-only evidence records from DisclosureGuard
  certificates and AFR receipts; the fleet's honest-verdict wording discipline.
- **New build (the substance of the proposal):** configurable data-store registry and
  store connectors/readers; subject-key search across memory exports, RAG/vector
  stores, logs and databases; personal-data flow mapping from declared config +
  instrumented events; retention validation against stored records; deletion-request
  test orchestration; post-deletion retrieval probes; and the per-location
  VERIFIED / UNVERIFIED / INACCESSIBLE report that never upgrades one store's
  no-match into a claim that all copies are deleted.
