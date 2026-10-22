import argparse, json, sys


class _Parser(argparse.ArgumentParser):
    """Usage errors exit 3 so they never collide with exit 2 (VULNERABLE)."""
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")
from . import core, probe

NOTE = "Only scan hosts you own or are explicitly authorized to test."

def main(argv=None):
    p = _Parser(prog="php2shell-check", description="Defensive checker for PHP2Shell (CVE-2026-109618/109619). " + NOTE)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", action="store_true", help="inspect the local php binary")
    g.add_argument("--url", help="explicit URL of a host you own (reads X-Powered-By/Server headers)")
    g.add_argument("--version-string", help="offline: classify a given version string (e.g. from dpkg/rpm)")
    p.add_argument("--php", default="php", help="php binary path for --local")
    p.add_argument("--sapi", help="SAPI to assume (e.g. fpm-fcgi, apache2handler)")
    p.add_argument("--i-own-this-host", action="store_true", help="required with --url: confirms authorization")
    p.add_argument("--json", action="store_true", help="JSON output")
    a = p.parse_args(argv)
    if a.local:
        ver, sapi, banner = probe.local(a.php)
        rep = core.build_report("localhost", "local-cli", ver or "", a.sapi or sapi, banner or "")
    elif a.url:
        if not a.i_own_this_host:
            p.error("--url requires --i-own-this-host. " + NOTE)
        xpb, server = probe.http(a.url)
        raw = xpb if "php" in xpb.lower() else (server if "php" in server.lower() else "")
        rep = core.build_report(a.url, "http-headers", raw, a.sapi, xpb + " " + server)
        rep["headers"] = {"X-Powered-By": xpb, "Server": server}
    else:
        rep = core.build_report("offline", "version-string", a.version_string, a.sapi, a.version_string)
    print(json.dumps(rep, indent=2) if a.json else core.to_text(rep))
    return {"fixed": 0, "vulnerable": 2, "unknown": 1}[rep["status"]]

if __name__ == "__main__":
    sys.exit(main())
