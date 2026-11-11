"""PII detector — rules adopted from DisclosureGuard's pii_scan pack.

Provenance (factual, required by the overlap gate): the rule set below is
ported from DisclosureGuard's ``app/pii_scan.py``, rules version 1.0.0 —
15 rules: secret shapes (AWS/GitHub/Anthropic/OpenAI/Stripe/Slack keys,
private-key blocks, generic credential assignments), Luhn-checked card
numbers, IBAN, US SSN, generic national-ID, email, phone, private-range IP.
Post-filters (example/fictional suppression, Luhn, private-range check),
masked excerpts, and the verdict discipline are carried over unchanged:
a clean result is "no findings with rules vX" — never "PII-free".

Adaptation for this tool: findings are re-anchored from (start, end) offsets
in one text blob to (store, record_id) locations across data stores.
"""
import re

PII_RULES_VERSION = "1.0.0"  # DisclosureGuard pii_scan pack version, kept for lineage


def _luhn_ok(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask(value, keep=2):
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


_EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net",
                    "test.com", "invalid", "localhost")
_FICTIONAL_PHONE_PREFIXES = ("555-01", "(555) 01", "555010", "+1-555-01")


def _looks_like_example(text):
    low = text.lower()
    if any(d in low for d in _EXAMPLE_DOMAINS):
        return True
    compact = re.sub(r"[\s\-().+]", "", low)
    if any(p.replace("-", "").replace("(", "").replace(")", "").replace("+", "")
           in compact for p in _FICTIONAL_PHONE_PREFIXES):
        return True
    return False


# (rule_id, category, severity, regex, suggestion) — ported verbatim from
# DisclosureGuard pii_scan rules v1.0.0; ids preserved so lineage is auditable.
_RULES = [
    ("PII-SECRET-001", "API key", "critical",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "Remove the key and rotate it in the provider console."),
    ("PII-SECRET-002", "API key", "critical",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
     "Remove the token and revoke it on GitHub."),
    ("PII-SECRET-003", "API key", "critical",
     re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
     "Remove the key and rotate it in the provider console."),
    ("PII-SECRET-004", "API key", "critical",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b"),
     "Remove the key and rotate it in the provider console."),
    ("PII-SECRET-005", "API key", "critical",
     re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b"),
     "Remove the key and rotate it in Stripe."),
    ("PII-SECRET-006", "API key", "critical",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
     "Remove the token and revoke it in Slack."),
    ("PII-SECRET-007", "Private key", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "Remove the key block immediately — it must never be stored in plain text."),
    ("PII-SECRET-008", "Secret value", "critical",
     re.compile(r"(?i)(api[_-]?key|secret|passwd|password)\s*[:=]\s*['\"]?[A-Za-z0-9\-_+/=]{12,}['\"]?"),
     "Remove the credential and rotate the secret."),
    ("PII-PAY-001", "Credit card", "critical",
     re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
     "Remove the card number — never store full PANs."),
    ("PII-PAY-002", "IBAN", "high",
     re.compile(r"\b[A-Z]{2}[0-9]{2}[ ]?(?:[0-9A-Z]{4}[ ]?){3,6}[0-9A-Z]{0,4}\b"),
     "Remove the IBAN or replace with a masked form."),
    ("PII-ID-001", "US Social Security number", "critical",
     re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
     "Remove the SSN — it must never appear in stored agent data."),
    ("PII-ID-002", "National ID (generic)", "high",
     re.compile(r"(?i)(?:national id|id number|passport|driver.?s.?licen[sc]e|cedula|curp|rfc)\s*(?:no\.?|number|#)?\s*[:#]?\s*[A-Z0-9\-]{5,20}\b"),
     "Remove the identifier or replace with [ID redacted]."),
    ("PII-CONTACT-001", "Email address", "high",
     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
     "Review whether this email needs to be retained in this store."),
    ("PII-CONTACT-002", "Phone number", "high",
     re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s\-.]?)?(?:\(?\d{3}\)?[\s\-.]?|\d{2,4}[\s\-.]?)\d{3}[\s\-.]?\d{4}(?!\d)"),
     "Review whether this phone number needs to be retained in this store."),
    ("PII-CONTACT-003", "IP address", "high",
     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     "Remove internal IP addresses from stored records."),
]

RULE_IDS = [r[0] for r in _RULES]


def _valid_hit(rule_id, match_text):
    if _looks_like_example(match_text):
        return False
    if rule_id == "PII-PAY-001":
        digits = re.sub(r"\D", "", match_text)
        if len(set(digits)) < 3:
            return False
        if not _luhn_ok(digits):
            return False
    if rule_id == "PII-CONTACT-003":
        octets = [int(x) for x in match_text.split(".")]
        if not all(0 <= o <= 255 for o in octets):
            return False
        o1, o2 = octets[0], octets[1]
        private = (o1 == 10 or (o1 == 172 and 16 <= o2 <= 31)
                   or (o1 == 192 and o2 == 168) or o1 == 127)
        if not private:
            return False
    return True


def scan_text(text):
    """Run the detector over one text blob. Findings carry masked excerpts only."""
    findings = []
    if not text:
        return findings
    for rule_id, category, severity, rx, suggestion in _RULES:
        for m in rx.finditer(text):
            hit = m.group(0)
            if not _valid_hit(rule_id, hit):
                continue
            findings.append({
                "rule_id": rule_id, "category": category, "severity": severity,
                "excerpt": _mask(hit), "start": m.start(), "end": m.end(),
                "suggestion": suggestion,
            })
    findings.sort(key=lambda f: (f["start"], -(f["end"] - f["start"])))
    deduped, last_end = [], -1
    for f in findings:
        if f["start"] >= last_end:
            deduped.append(f)
            last_end = f["end"]
    return deduped


def scan_record(store_name, record_id, text):
    """Re-anchor blob findings to a (store, record_id) location."""
    out = []
    for f in scan_text(text):
        out.append({
            "store": store_name, "record_id": record_id,
            "rule_id": f["rule_id"], "category": f["category"],
            "severity": f["severity"], "excerpt": f["excerpt"],
            "suggestion": f["suggestion"], "rules_version": PII_RULES_VERSION,
        })
    return out
