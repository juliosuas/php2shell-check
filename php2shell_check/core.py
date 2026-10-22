"""Pure logic: parse versions, classify status. No network, no exploit code."""
import re

CVES = ["CVE-2026-109618", "CVE-2026-109619"]
# Upstream fixed releases (php.net advisory, 2026-10-21).
FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
# Web-serving SAPIs named in the advisory; mod_php considered highest risk.
SAPI_RISK = {
    "apache2handler": "high (mod_php: advisory rates this highest risk)",
    "fpm-fcgi": "affected (web-serving)",
    "cgi-fcgi": "affected (web-serving)",
    "litespeed": "affected (web-serving)",
    "frankenphp": "affected (web-serving)",
    "cli": "low (CLI does not serve web requests; check the web SAPI separately)",
}
_VER = re.compile(r"(\d+)\.(\d+)\.(\d+)([^\s;,()]*)")
_DISTRO = re.compile(r"(ubuntu|deb|el\d|\.el|fc\d|amzn|suse|alpine|-r\d|\+|~|sury|remi)", re.I)


def parse_version(text):
    """Return (tuple, suffix) or None. suffix holds distro build info, e.g. '-1ubuntu2.20'."""
    m = _VER.search(text or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), m.group(4)


def detect_distro_build(suffix, extra=""):
    return bool(_DISTRO.search((suffix or "") + " " + (extra or "")))


def classify(version, suffix="", extra=""):
    """Return dict(status, reason). status in fixed|vulnerable|unknown."""
    major_minor = version[:2]
    distro = detect_distro_build(suffix, extra)
    if version < (5, 4, 0):
        return {"status": "unknown", "reason": "Older than 5.4; not listed in public advisories. Unsupported anyway: upgrade."}
    if major_minor in FIXED:
        fixed = FIXED[major_minor]
        if version >= fixed:
            return {"status": "fixed", "reason": "Upstream version >= %s.%s.%s" % fixed}
        if distro:
            return {"status": "unknown", "reason": "Upstream %s.%s.%s < fixed %s.%s.%s, but distro build detected: "
                    "backport possible. Unknown - check distro advisory." % (version + fixed)}
        return {"status": "vulnerable", "reason": "Below fixed release %s.%s.%s" % fixed}
    if version[:2] > (8, 5):
        return {"status": "unknown", "reason": "Newer branch than advisory covers; verify with php.net."}
    # 5.4 - 8.1: EOL upstream, no official release fix
    if distro:
        return {"status": "unknown", "reason": "EOL branch (<=8.1) with distro build: only a vendor backport can fix it. "
                "Unknown - check distro advisory (Debian/Ubuntu/RHEL/etc.)."}
    return {"status": "vulnerable", "reason": "EOL branch (<=8.1): no upstream fix release. Upgrade to 8.2.35+ or use a vendor backport."}


MITIGATION = [
    "Upgrade to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or apply your vendor's backported package.",
    "Restart PHP workers (php-fpm, Apache) and rebuild/redeploy container images after patching.",
    "If you cannot patch now: follow the php.net temporary mitigations (e.g. session.upload_progress.enabled=0, "
    "review memory_limit/post_max_size). These are partial, NOT a fix.",
    "Check appliances/products that bundle PHP separately; apply vendor updates.",
    "Monitor for PHP workers spawning shells and memory-exhaustion errors during request init.",
]


def build_report(target, method, raw_version, sapi=None, extra=""):
    parsed = parse_version(raw_version)
    rep = {"target": target, "method": method, "cves": CVES, "raw_version": raw_version, "sapi": sapi}
    if not parsed:
        rep.update(status="unknown", reason="PHP version not detected (header hidden or PHP absent). Check on the host with php -v.",
                   version=None, sapi_risk=None)
    else:
        v, suffix = parsed
        rep["version"] = "%d.%d.%d%s" % (v + (suffix,))
        rep.update(classify(v, suffix, extra))
        rep["sapi_risk"] = SAPI_RISK.get((sapi or "").lower(), "unknown SAPI" if sapi else "not detected")
    rep["mitigation"] = MITIGATION if rep["status"] != "fixed" else ["Patched per version string. Confirm workers were restarted."]
    return rep


def to_text(rep):
    lines = ["php2shell-check report (%s)" % ", ".join(rep["cves"]),
             "  target : %s (%s)" % (rep["target"], rep["method"]),
             "  version: %s" % (rep.get("version") or "not detected"),
             "  sapi   : %s -> %s" % (rep.get("sapi") or "n/a", rep.get("sapi_risk") or "n/a"),
             "  STATUS : %s" % rep["status"].upper(),
             "  reason : %s" % rep["reason"], "  mitigation:"]
    lines += ["    - " + m for m in rep["mitigation"]]
    return "\n".join(lines)
