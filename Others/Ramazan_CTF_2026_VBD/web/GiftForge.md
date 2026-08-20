
---

# GiftForge Challenge Write-up

## Challenge Information

- **Name:** GiftForge
    
- **Difficulty:** Very Easy
    
- **Category:** Web / Logic Bypass
    
- **Target:** `http://82.29.170.47:36364/`
    
- **Flag:** `VBD{n0rmalization_1s_3asy_1337_a660d3909fa8bb7015edf779ebefb9d0}`
    

---

## 1. Initial Analysis

The application is a gift card store where users can sign up, log in, and buy gift cards. The "Secret Flag" gift card is priced at **$1337.00**, but users start with a lower balance. To obtain the flag, we must increase our balance by redeeming a special code.

### The Vulnerability

In `src/app.py`, the `/redeem` route contains a Unicode Normalization vulnerability:

Python

```
@app.route('/redeem', methods=['GET', 'POST'])
@login_required
def redeem():
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        
        # Check 1: Strict check for the expired code
        if code == "GIFT500":
            flash('This special offer has expired.', 'error')
            return redirect(url_for('redeem'))
        
        # Unicode Normalization logic (NFKD)
        code = "".join(c for c in unicodedata.normalize('NFKD', code) if not unicodedata.combining(c)).upper()
        
        # Check 2: Check normalized code for balance addition
        if code == "GIFT500":
            current_user.balance += 500.0
            db.session.commit()
            flash('500 credits added to your account.', 'success')
            return redirect(url_for('store'))
```

The logic prevents the literal string `GIFT500` from being used, but then normalizes the input using **NFKD** (Normalization Form Compatibility Decomposition) and strips combining characters (accents).

---

## 2. Exploitation Steps

### Step 1: Bypassing the Expired Check

To trigger the $500 bonus, we need a string that is **not** exactly `GIFT500` but becomes `GIFT500` after normalization. By using the character `Í` (Latin Capital Letter I with Acute), we can bypass the first `if` statement.

- **Payload:** `GÍFT500`
    
- **Logic:** 1. `GÍFT500 == GIFT500` is **False**. (Passes first check)
    
    2. `unicodedata.normalize('NFKD', 'GÍFT500')` decomposes `Í` into `I` + `´`.
    
    3. The filter removes the accent `´`, leaving `GIFT500`. (Triggers balance addition)
    

### Step 2: Increasing Balance

1. Navigate to the `/redeem` page.
    
2. Enter `GÍFT500` into the redemption box.
    
3. The account balance increases by **$500**.
    

### Step 3: Purchasing the Flag

With the updated balance ($1000 initial + $500 bonus = $1500 total), we go to the Store page and purchase the **Secret Flag** for **$1337.00**.

### Step 4: Retrieving the Flag

After the purchase, navigate to the **Profile** page. The gift card code for the "Secret Flag" contains the actual flag.

---

## 3. Conclusion

The challenge demonstrates why input validation must be performed **after** all normalization and sanitization steps. If the normalization happens after a security check, an attacker can use visually similar or decomposable characters to bypass filters.

---

