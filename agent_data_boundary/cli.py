"""CLI: agent-data-boundary {inventory|scan|map|retention-check|deletion-test}"""
import argparse
import json
import sys

from . import engine
from .config import load_config, ConfigError


def _emit(data, out):
    text = json.dumps(data, indent=2)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="agent-data-boundary",
        description="Cross-store personal-data lifecycle testing for agent "
                    "systems (local files only).")
    p.add_argument("--config", required=True, help="path to config JSON")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("inventory", "scan", "map", "retention-check"):
        sp = sub.add_parser(name)
        sp.add_argument("--out", help="also write JSON output to this file")
    sp = sub.add_parser("deletion-test")
    sp.add_argument("--email", help="subject email identifier")
    sp.add_argument("--subject-id", help="subject id identifier")
    sp.add_argument("--workdir", help="directory for working copies")
    sp.add_argument("--out", help="also write JSON output to this file")
    args = p.parse_args(argv)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print("config error: %s" % exc, file=sys.stderr)
        return 2
    if args.command == "inventory":
        _emit(engine.inventory(config), args.out)
    elif args.command == "scan":
        _emit(engine.scan(config), args.out)
    elif args.command == "map":
        result = engine.data_map(config, engine.scan(config))
        _emit(result, args.out)
        print("\n" + result["mermaid"])
    elif args.command == "retention-check":
        _emit(engine.retention_check(config), args.out)
    elif args.command == "deletion-test":
        ids = [x for x in (args.email, args.subject_id) if x]
        if not ids:
            print("deletion-test needs --email and/or --subject-id", file=sys.stderr)
            return 2
        _emit(engine.deletion_test(config, ids, workdir=args.workdir), args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
