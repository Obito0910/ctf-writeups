# Overheard at Breakfast — OSINT Writeup

**Author:** Obito Uchiha — Team AKATSUKI **Category:** OSINT **Difficulty:** Easy **Points:** 60

---

## 🧭 Recon

The challenge provides a single screenshot of a Slack-style DM between two guests at a hotel — `Ponzi - Influencer` and `Lambo!`. Reading the conversation carefully (per @0xMia's hint: _"y'all need to actually READ what they said, not just skim it"_), one exchange stands out:

> **Lambo!:** _"...I used to use this free tool that let me upload my profile and link other media accounts, was neat, until I wiped everything. Started with a **G** if I remember correctly. But if anything this is my best way of communication:_ `lambobytelotushotel@gmail.com`"

Two facts fall out of this line:

1. A free profile/social-linking tool starting with **G** → strongly points to **Gravatar** (Globally Recognized Avatar), which builds a public profile keyed to an email address hash and lets users attach linked/verified social accounts.
2. A concrete **email address**: `lambobytelotushotel@gmail.com`

## 🔍 Vulnerability / Exposure Analysis

Gravatar profiles are looked up via a hash of the (lowercased, trimmed) email address:

- Legacy API → MD5 hash
- Current v3 API → SHA-256 hash

Since Gravatar profile data is public by design once created, anyone who knows (or can guess) the underlying email can pull the account's profile — display name, bio, location, linked accounts — just by hashing it. This is the classic "email hash OSINT" pivot: an email a person considers "private enough to hand out in a DM" is not actually private once it's tied to a Gravatar profile, because the _hash_ of it is the only thing gatekeeping public lookup, and hashes of known/guessed plaintexts are trivial to compute.

## ⚙️ Exploitation Steps

**1. Hash the email (SHA-256, used by Gravatar's v3 Profiles API):**

```bash
echo -n "lambobytelotushotel@gmail.com" | sha256sum
# d43faafe9d7f056793bd037b8d6e321acad985c222d83775b10d6539e301e931
```

**2. Query the Gravatar public Profiles API with the hash:**

```bash
curl https://api.gravatar.com/v3/profiles/d43faafe9d7f056793bd037b8d6e321acad985c222d83775b10d6539e301e931 | jq
```

**3. Profile resolves — full public data returned unauthenticated:**

```json
{
  "display_name": "Lambo",
  "profile_url": "https://gravatar.com/cheerfullysongf28e3c3716",
  "location": "Byte Lotus Hotel",
  "description": "Funny thing about email hashes, they follow you places you didn't expect. Glad you found the right corner of the internet! Here is your prize: VEhNe1MzY3JlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9",
  ...
}
```

The `description` field contains a Base64-encoded string — the flag.

**4. Decode:**

```bash
echo VEhNe1MzY3JlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9 | base64 -d
# THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}
```

## 🚩 Flag

```
THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}
```

## 🌱 Root Cause

The exposure isn't a bug in Gravatar's API — it's working exactly as documented. The real weakness is **operational/privacy hygiene on the user's side**:

- Lambo shared a "throwaway" personal email in what felt like a low-stakes DM, not realizing that email is the sole key needed to deanonymize a linked public profile.
- Gravatar profile lookups require no authentication and no rate-limit-defeating tricks — a plain hash of a known email is enough (100 unauthenticated requests/hour by default).
- The victim's own message ("started with a G... used to link other media accounts") was effectively free reconnaissance, narrowing the search space for an attacker/analyst from "any OSINT tool" down to one specific platform.

## 🛡️ Remediation / Takeaways

- Don't assume an email address is "safe" to share just because it's not your primary/main one — any service tying identity data to an email hash (Gravatar being the classic example) can be reversed the moment the plaintext leaks.
- Gravatar users should periodically audit `gravatar.com/profile/*` visibility settings — `hidden_verified_accounts`, `hidden_contact_info`, etc. — and consider deleting stale profiles ("wiped everything," per Lambo, apparently didn't fully take).
- From a blue-team/analyst angle: email-hash pivoting (Gravatar, HIBP, Skype/Steam old lookups, etc.) remains one of the highest-signal, lowest-effort OSINT techniques — always worth checking in a person-of-interest investigation, and worth defending against in an OPSEC review.

---

_Writeup by Obito Uchiha — Team AKATSUKI_