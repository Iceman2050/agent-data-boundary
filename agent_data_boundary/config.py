"""Config loading. JSON only (stdlib); the format is documented in the README.

A config declares data stores:
  {"stores": [{"name": ..., "type": "sqlite|jsonl|json|textdir",
               "path": ..., "retention_days": int|null,
               "retention_basis": str, "deletion_test_safe": bool,
               "table": optional sqlite table name}]}
Paths are resolved relative to the config file's directory.
"""
import json
import os

STORE_TYPES = ("sqlite", "jsonl", "json", "textdir")


class ConfigError(Exception):
    pass


def load_config(path):
    if not os.path.isfile(path):
        raise ConfigError("config file not found: %s" % path)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigError("config is not valid JSON: %s" % exc)
    stores = data.get("stores")
    if not isinstance(stores, list) or not stores:
        raise ConfigError("config must contain a non-empty 'stores' list")
    base = os.path.dirname(os.path.abspath(path))
    seen = set()
    for s in stores:
        for key in ("name", "type", "path"):
            if key not in s:
                raise ConfigError("store entry missing '%s': %r" % (key, s))
        if s["type"] not in STORE_TYPES:
            raise ConfigError("store %r has unknown type %r (expected one of %s)"
                              % (s["name"], s["type"], ", ".join(STORE_TYPES)))
        if s["name"] in seen:
            raise ConfigError("duplicate store name: %r" % s["name"])
        seen.add(s["name"])
        if not os.path.isabs(s["path"]):
            s["path"] = os.path.join(base, s["path"])
        s.setdefault("deletion_test_safe", False)
        s.setdefault("retention_days", None)
        s.setdefault("retention_basis", "")
    return data
