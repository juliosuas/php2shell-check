"""Collectors. Local: runs php/php-fpm/apachectl version/module listings. HTTP: one plain GET,
reads headers only. No payloads."""
import glob, os, re, shutil, socket, ssl, subprocess, urllib.error, urllib.request

_V = re.compile(r"PHP (\d+\.\d+\.\d+\S*)\s*\(([^)]*)\)")
MODULE_GLOBS = ["/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
                "/usr/lib/httpd/modules/libphp*.so", "/usr/local/apache2/modules/libphp*.so",
                "/usr/libexec/apache2/libphp*.so"]
FPM_NAMES = ["php-fpm"] + ["php-fpm%s" % v for v in ("8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4", "7.3", "7.2", "7.1", "7.0", "5.6")]
FPM_DIRS = ["/usr/sbin", "/usr/local/sbin", "/opt/remi/*/root/usr/sbin"]


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.stdout + r.stderr
    except (OSError, subprocess.SubprocessError):
        return ""


def local(php="php"):
    """CLI runtime: returns (version, sapi, banner)."""
    if not shutil.which(php):
        return None, None, ""
    out = _run([php, "-r", "echo PHP_VERSION, '|', php_sapi_name();"])
    banner = _run([php, "-v"])
    if "|" not in out:
        return banner, "cli", banner
    ver, sapi = out.strip().split("|", 1)
    return ver, sapi, banner


def fpm_binaries():
    found = []
    for n in FPM_NAMES:
        w = shutil.which(n)
        if w:
            found.append(w)
    for d in FPM_DIRS:
        for g in glob.glob(os.path.join(d, "php-fpm*")):
            found.append(g)
    seen, uniq = set(), []
    for f in found:
        k = os.path.realpath(f)
        if k not in seen:
            seen.add(k); uniq.append(f)
    return uniq


def fpm_runtimes():
    res = []
    for b in fpm_binaries():
        out = _run([b, "-v"])
        m = _V.search(out)
        res.append({"label": "php-fpm (%s)" % b, "raw": m.group(1) if m else "", "sapi": "fpm-fcgi"})
    return res


def apache_modphp():
    res = []
    for ctl in ("apachectl", "apache2ctl", "httpd"):
        if shutil.which(ctl):
            mods = _run([ctl, "-M"])
            if re.search(r"php\d*_module", mods):
                res.append({"label": "mod_php (%s -M)" % ctl, "raw": "", "sapi": "apache2handler"})
                break
    for pattern in MODULE_GLOBS:
        for so in glob.glob(pattern):
            res.append({"label": "mod_php (%s)" % so, "raw": "", "sapi": "apache2handler"})
    return res


def local_runtimes(php="php"):
    """Every PHP runtime found: CLI + php-fpm + mod_php."""
    rts = []
    ver, sapi, _ = local(php)
    rts.append({"label": "cli (%s)" % php, "raw": ver or "", "sapi": sapi or "cli"})
    rts += fpm_runtimes()
    rts += apache_modphp()
    return rts


def http(url, timeout=10):
    """Returns (x_powered_by_values:list, server:str, error:str|None). Never raises on network errors."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "php2shell-check/0.1 (defensive version check)"})
    try:
        h = urllib.request.urlopen(req, timeout=timeout).headers
    except urllib.error.HTTPError as e:
        h = e.headers
    except urllib.error.URLError as e:
        return [], "", "network error: %s" % (e.reason,)
    except (socket.timeout, TimeoutError):
        return [], "", "timeout after %ss" % timeout
    except ssl.SSLError as e:
        return [], "", "TLS error: %s" % e
    except (OSError, ValueError) as e:
        return [], "", "%s: %s" % (type(e).__name__, e)
    return list(h.get_all("X-Powered-By") or []), h.get("Server", "") or "", None
