import json, pytest
from php2shell_check import core, cli, probe

@pytest.mark.parametrize("v,exp", [
    ("8.5.12", "fixed"), ("8.5.11", "vulnerable"), ("8.4.27", "fixed"), ("8.4.26", "vulnerable"),
    ("8.3.36", "fixed"), ("8.3.35", "vulnerable"), ("8.2.35", "fixed"), ("8.2.0", "vulnerable"),
    ("8.1.30", "vulnerable"), ("7.4.33", "vulnerable"), ("5.3.29", "unknown"), ("9.0.0", "unknown"),
])
def test_upstream(v, exp):
    assert core.build_report("t", "x", v)["status"] == exp

@pytest.mark.parametrize("v", ["8.1.2-1ubuntu2.20", "7.4.33-1+deb11u7", "8.0.30-1.el9_4", "8.3.6-0ubuntu0.24.04.3"])
def test_distro_is_unknown(v):
    assert core.build_report("t", "x", v)["status"] == "unknown"

def test_distro_new_enough_is_fixed():
    assert core.build_report("t", "x", "8.3.36-1+ubuntu24.04.1+deb.sury.org+1")["status"] == "fixed"

def test_header_and_none():
    assert core.build_report("t", "x", "PHP/8.4.10")["status"] == "vulnerable"
    assert core.build_report("t", "x", "")["status"] == "unknown"

def test_sapi_risk():
    assert core.build_report("t", "x", "8.4.1", "apache2handler")["sapi_risk"].startswith("high")

def test_url_requires_consent():
    with pytest.raises(SystemExit):
        cli.main(["--url", "http://example.invalid"])

def test_url_headers(monkeypatch, capsys):
    monkeypatch.setattr(probe, "http", lambda u: ("PHP/8.2.35", "nginx"))
    rc = cli.main(["--url", "https://mine.test", "--i-own-this-host", "--json"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["status"] == "fixed"

def test_local(monkeypatch, capsys):
    monkeypatch.setattr(probe, "local", lambda php="php": ("8.5.11", "cli", "PHP 8.5.11 (cli)"))
    assert cli.main(["--local"]) == 2
    assert "VULNERABLE" in capsys.readouterr().out


def test_url_without_consent_exits_3_not_vulnerable_code():
    import subprocess, sys
    r = subprocess.run([sys.executable, "-m", "php2shell_check", "--url", "https://example.invalid"], capture_output=True, text=True)
    assert r.returncode == 3
