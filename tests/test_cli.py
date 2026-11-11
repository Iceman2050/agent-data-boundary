import json

import make_fixtures
from agent_data_boundary.cli import main


def test_cli_inventory(tmp_path, capsys):
    cfg = make_fixtures.build(str(tmp_path))
    assert main(["--config", cfg, "inventory"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert any(s["status"] == "INACCESSIBLE" for s in data["stores"])


def test_cli_deletion_test(tmp_path, capsys):
    cfg = make_fixtures.build(str(tmp_path))
    rc = main(["--config", cfg, "deletion-test",
               "--email", make_fixtures.SUBJECT_EMAIL,
               "--subject-id", make_fixtures.SUBJECT_ID,
               "--workdir", str(tmp_path / "w")])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    verdicts = {r["verdict"] for r in data["results"]}
    assert {"VERIFIED", "UNVERIFIED", "INACCESSIBLE", "NOT_FOUND"} <= verdicts


def test_cli_missing_config(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "nope.json"), "inventory"]) == 2
