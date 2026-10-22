# php2shell-check

Defensive, read-only checker for **PHP2Shell** (CVE-2026-109618, CVE-2026-109619).
It reports PHP version + SAPI and compares against the fixed releases. **No exploit code, no payloads.**

> Only scan hosts you own or are explicitly authorized to test. `--url` requires `--i-own-this-host`.

## Fixed versions (php.net advisory, 2026-10-21)
8.5.12 · 8.4.27 · 8.3.36 · 8.2.35. PHP ≤ 8.1 is EOL upstream (source backports exist for 7.4/8.0/8.1; rely on your vendor's packages).
Affected web SAPIs: PHP-FPM, Apache mod_php (highest risk), php-cgi, FrankenPHP, LiteSpeed.

## Usage (Python 3.8+, stdlib only)
```
python3 -m php2shell_check --local                     # local php binary
python3 -m php2shell_check --url https://my.host --i-own-this-host
python3 -m php2shell_check --version-string "$(dpkg-query -W -f='${Version}' php8.1-fpm)"
python3 -m php2shell_check --local --sapi fpm-fcgi --json
```
Exit codes: 0 fixed, 1 unknown, 2 vulnerable, 3 usage error.

Run tests from the repo root with `pytest` (configured in `pyproject.toml`), or `pip install -e .` to get the `php2shell-check` command.

## What it detects / does not
- `--local` (no `--sapi`) checks every runtime it finds: CLI, `php-fpm*` binaries (`php-fpm -v`, `php-fpm8.3`, ...),
  and Apache mod_php (`apachectl/apache2ctl/httpd -M`, `libphp*.so` in common module dirs). Worst status sets the exit code.
  If no web SAPI is found the report says **"CLI only, web SAPI not checked"**.
- mod_php's version can't be read from the module: reported UNKNOWN; check the package (`dpkg -l 'libapache2-mod-php*'`, `rpm -q php`).
- Distro detection looks only at the PHP version suffix (`-1ubuntu2.20`, `+deb11u7`, `.el9`), never at `Server:` headers.
- Missing `X-Powered-By` is UNKNOWN, never FIXED: CDNs/proxies or `expose_php=Off` hide it.
- Network/DNS/TLS/timeouts -> UNKNOWN with the cause. Usage errors exit 3.
- Detects: version from `php` CLI, `X-Powered-By`/`Server` headers, or a supplied package version string; SAPI risk.
- `unknown — check distro advisory` when a distro build (Debian/Ubuntu/RHEL/sury/remi…) is below the upstream fix, since backports keep the old upstream number.
- Does NOT: test exploitability, see hidden headers (`expose_php=Off`), confirm workers were restarted, inspect bundled PHP in appliances, or know distro backport versions.
- Does not find PHP in containers, chroots, non-standard paths, or PHP-FPM pools that aren't installed as binaries on PATH/sbin.

## Tests
`python3 -m pytest -q`

## References
- https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- https://github.com/NCSC-NL/php2shell
- https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
- https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619

MIT License.
