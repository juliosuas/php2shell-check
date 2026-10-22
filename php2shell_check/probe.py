"""Collectors. Local: runs `php` binary. HTTP: one plain GET, reads headers only. No payloads."""
import subprocess, urllib.request, urllib.error, shutil

def local(php="php"):
    if not shutil.which(php):
        return None, None, ""
    out = subprocess.run([php, "-r", "echo PHP_VERSION, '|', php_sapi_name();"], capture_output=True, text=True, timeout=15)
    if out.returncode != 0 or "|" not in out.stdout:
        v = subprocess.run([php, "-v"], capture_output=True, text=True, timeout=15).stdout
        return v, "cli", v
    ver, sapi = out.stdout.strip().split("|", 1)
    banner = subprocess.run([php, "-v"], capture_output=True, text=True, timeout=15).stdout
    return ver, sapi, banner

def http(url, timeout=10):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "php2shell-check/0.1 (defensive version check)"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        h = resp.headers
    except urllib.error.HTTPError as e:
        h = e.headers
    xpb, server = h.get("X-Powered-By", ""), h.get("Server", "")
    return xpb, server
