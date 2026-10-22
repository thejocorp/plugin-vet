"""Each fixture is a tiny synthetic add-on that should trip exactly one kind of check."""
import pathlib

import pytest

from plugin_vet import Policy, scan

FIX = pathlib.Path(__file__).parent / "fixtures"


def cats(name):
    return {f.category for f in scan(FIX / name).findings}


def test_clean_skill_has_no_findings():
    result = scan(FIX / "clean-skill")
    assert result.kind == "skill"
    assert result.findings == []


def test_every_call_hook():
    assert "every-call-hook" in cats("hooky-plugin")
    assert scan(FIX / "hooky-plugin").kind == "claude-plugin"


def test_telemetry():
    assert "telemetry" in cats("telemetry-tool")


def test_unpinned_mcp():
    result = scan(FIX / "unpinned-mcp")
    assert "unpinned-fetch" in {f.category for f in result.findings}
    assert result.kind == "mcp-server"


def test_committed_secret():
    assert "committed-secret" in cats("leaky")


def test_pipe_to_shell():
    assert "pipe-to-shell" in cats("pipe-install")


def test_policy_fail_threshold():
    result = scan(FIX / "telemetry-tool")   # telemetry is medium by default
    policy = Policy()
    assert policy.fails(result.findings, "medium") is True
    assert policy.fails(result.findings, "high") is False


def test_policy_override():
    policy = Policy({"telemetry": "high"})
    result = scan(FIX / "telemetry-tool")
    assert policy.fails(result.findings, "high") is True


def test_missing_target():
    with pytest.raises(NotADirectoryError):
        scan(FIX / "does-not-exist")


def test_secret_in_test_file_is_ignored():
    # a fake key in a *_test.go file is fixture data, not a committed secret
    assert "committed-secret" not in cats("secret-in-test")
