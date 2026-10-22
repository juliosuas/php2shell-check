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
    monkeypatch.setattr(probe, "http", lambda u: (["PHP/8.2.35"], "nginx", None))
    rc = cli.main(["--url", "https://mine.test", "--i-own-this-host", "--json"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["status"] == "fixed"

def test_local(monkeypatch, capsys):
    monkeypatch.setattr(probe, "local", lambda php="php": ("8.5.11", "cli", "PHP 8.5.11 (cli)"))
    monkeypatch.setattr(probe, "fpm_runtimes", lambda: [])
    monkeypatch.setattr(probe, "apache_modphp", lambda: [])
    assert cli.main(["--local"]) == 2
    assert "VULNERABLE" in capsys.readouterr().out


def test_url_without_consent_exits_3_not_vulnerable_code():
    import subprocess, sys
    r = subprocess.run([sys.executable, "-m", "php2shell_check", "--url", "https://example.invalid"], capture_output=True, text=True)
    assert r.returncode == 3


# --- Gilfoyle review ---
import subprocess as _sp

def _fake_run(outputs):
    def run(cmd, **kw):
        key = " ".join(cmd)
        for k, v in outputs.items():
            if k in key:
                return _sp.CompletedProcess(cmd, 0, v, "")
        return _sp.CompletedProcess(cmd, 1, "", "")
    return run

def test_fpm_detected_worst_drives_exit(monkeypatch, capsys):
    monkeypatch.setattr(probe.shutil, "which", lambda n: "/usr/bin/" + n if n in ("php", "php-fpm8.3") else None)
    monkeypatch.setattr(probe.glob, "glob", lambda p: [])
    monkeypatch.setattr(probe.subprocess, "run", _fake_run({
        "-r": "8.3.36|cli", "php -v": "PHP 8.3.36 (cli)",
        "php-fpm8.3 -v": "PHP 8.3.30 (fpm-fcgi) (built: x)"}))
    rc = cli.main(["--local", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2 and out["status"] == "vulnerable" and "note" not in out
    st = {r["target"]: r["status"] for r in out["runtimes"]}
    assert st["cli (php)"] == "fixed" and st["php-fpm (/usr/bin/php-fpm8.3)"] == "vulnerable"

def test_modphp_via_apachectl_and_so(monkeypatch, capsys):
    monkeypatch.setattr(probe.shutil, "which", lambda n: "/usr/bin/" + n if n in ("php", "apache2ctl") else None)
    monkeypatch.setattr(probe.glob, "glob", lambda p: ["/usr/lib/apache2/modules/libphp8.1.so"] if p.startswith("/usr/lib/apache2") else [])
    monkeypatch.setattr(probe.subprocess, "run", _fake_run({
        "-r": "8.4.27|cli", "php -v": "PHP 8.4.27 (cli)", "apache2ctl -M": " php_module (shared)\n"}))
    rc = cli.main(["--local", "--json"])
    out = json.loads(capsys.readouterr().out)
    sapis = [r["sapi"] for r in out["runtimes"]]
    assert sapis.count("apache2handler") == 2 and rc == 1 and out["status"] == "unknown"

def test_cli_only_label(monkeypatch, capsys):
    monkeypatch.setattr(probe.shutil, "which", lambda n: "/usr/bin/php" if n == "php" else None)
    monkeypatch.setattr(probe.glob, "glob", lambda p: [])
    monkeypatch.setattr(probe.subprocess, "run", _fake_run({"-r": "8.5.12|cli", "php -v": "PHP 8.5.12 (cli)"}))
    assert cli.main(["--local"]) == 0
    assert "CLI only, web SAPI not checked" in capsys.readouterr().out

def test_ubuntu_server_header_not_distro(monkeypatch, capsys):
    monkeypatch.setattr(probe, "http", lambda u: (["PHP/8.4.26"], "Apache/2.4.58 (Ubuntu)", None))
    assert cli.main(["--url", "https://mine.test", "--i-own-this-host"]) == 2
    assert "VULNERABLE" in capsys.readouterr().out

@pytest.mark.parametrize("suffix,exp", [("-1ubuntu2.20", True), ("-1+deb11u7", True), ("-1.el9_4", True),
    ("-r0", True), ("+sury", True), ("", False), ("RC1", False), ("-dev", False), ("debug", False)])
def test_distro_regex_suffix_only(suffix, exp):
    assert core.detect_distro_build(suffix) is exp

def test_multiple_x_powered_by(monkeypatch, capsys):
    monkeypatch.setattr(probe, "http", lambda u: (["ASP.NET", "PHP/8.2.35", "PHP/8.3.1"], "nginx", None))
    rc = cli.main(["--url", "https://mine.test", "--i-own-this-host", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2 and len(out["runtimes"]) == 2

@pytest.mark.parametrize("exc", [
    __import__("urllib.error").error.URLError("Name or service not known"),
    __import__("socket").timeout("timed out"),
    __import__("ssl").SSLError("cert verify failed"),
    ConnectionRefusedError("refused")])
def test_http_errors_unknown(monkeypatch, capsys, exc):
    def boom(*a, **k): raise exc
    monkeypatch.setattr(probe.urllib.request, "urlopen", boom)
    rc = cli.main(["--url", "https://mine.test", "--i-own-this-host"])
    out = capsys.readouterr().out
    assert rc == 1 and "Could not fetch" in out and "Traceback" not in out

def test_missing_header_reason(monkeypatch, capsys):
    monkeypatch.setattr(probe, "http", lambda u: ([], "cloudflare", None))
    assert cli.main(["--url", "https://mine.test", "--i-own-this-host"]) == 1
    o = capsys.readouterr().out
    assert "does NOT mean FIXED" in o and "expose_php=Off" in o
