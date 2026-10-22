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
        if a.sapi:
            ver, sapi, banner = probe.local(a.php)
            reps = [core.build_report("cli (%s)" % a.php, "local-cli", ver or "", a.sapi)]
            note = "SAPI forced via --sapi"
        else:
            rts = probe.local_runtimes(a.php)
            reps = []
            for r in rts:
                rr = core.build_report(r["label"], "local", r["raw"], r["sapi"])
                if r["sapi"] == "apache2handler" and not r["raw"]:
                    rr["reason"] = ("mod_php present but its version can't be read from the module. "
                                    "Check the package: dpkg -l 'libapache2-mod-php*' / rpm -q php.")
                reps.append(rr)
            web = [r for r in rts if r["sapi"] != "cli"]
            note = None if web else "CLI only, web SAPI not checked (no php-fpm or mod_php found)"
        rep = core.combine("localhost", "local", reps, note)
        out = json.dumps(rep, indent=2) if a.json else core.combined_text(rep)
    elif a.url:
        if not a.i_own_this_host:
            p.error("--url requires --i-own-this-host. " + NOTE)
        xpbs, server, err = probe.http(a.url)
        php_vals = [x for x in xpbs if "php" in x.lower()]
        if not php_vals and "php" in server.lower():
            php_vals = [server]
        if err:
            reps = [core.build_report(a.url, "http-headers", "", a.sapi, reason="Could not fetch: %s" % err)]
        elif not php_vals:
            reps = [core.build_report(a.url, "http-headers", "", a.sapi)]
        else:
            reps = [core.build_report(a.url, "http-headers", v, a.sapi) for v in php_vals]
        for r in reps:
            r["headers"] = {"X-Powered-By": xpbs, "Server": server}
        rep = core.combine(a.url, "http-headers", reps) if len(reps) > 1 else reps[0]
        out = json.dumps(rep, indent=2) if a.json else (core.combined_text(rep) if len(reps) > 1 else core.to_text(rep))
    else:
        rep = core.build_report("offline", "version-string", a.version_string, a.sapi)
        out = json.dumps(rep, indent=2) if a.json else core.to_text(rep)
    print(out)
    return {"fixed": 0, "vulnerable": 2, "unknown": 1}[rep["status"]]

if __name__ == "__main__":
    sys.exit(main())
