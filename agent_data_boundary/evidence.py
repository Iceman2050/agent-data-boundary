"""Hash-chained evidence records (fleet idiom, cf. DisclosureGuard
sanitization certificates): each report entry chains to the previous entry's
hash, so a report cannot be silently edited after the fact. Hashes cover
metadata only — never the sensitive values themselves.
"""
import hashlib
import json

GENESIS = "GENESIS"


def entry_hash(prev_hash, payload):
    material = prev_hash + "|" + json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def chain(entries):
    """Attach prev_hash/hash to each entry dict in order. Returns the entries."""
    prev = GENESIS
    for e in entries:
        h = entry_hash(prev, {k: v for k, v in e.items()
                              if k not in ("hash", "prev_hash")})
        e["prev_hash"] = prev
        e["hash"] = h
        prev = h
    return entries


def verify_chain(entries):
    prev = GENESIS
    for e in entries:
        expect = entry_hash(prev, {k: v for k, v in e.items()
                                   if k not in ("hash", "prev_hash")})
        if expect != e.get("hash") or e.get("prev_hash") != prev:
            return False
        prev = e["hash"]
    return True
