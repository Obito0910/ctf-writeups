# Phantom Device — Writeup

**Category:** Pwn / Binary Exploitation **Points:** 200 **Author:** NomanProdhan **Flag:** `BDSEC{ph4nt0m_h4ndl35_n3v3r_d13}`

## Challenge

> The device is online. Something is still attached.

We're given a stripped, non-PIE x86-64 ELF (`phantom_device`) and a `nc` endpoint. Running it presents a menu-driven "driver interface":

```
1. Allocate device      6. Create session
2. Duplicate handle     7. Inspect session
3. Read device          8. Request privileged data
4. Write device          9. Destroy session
5. Release handle       10. Exit
```

Two independent object tables live in the binary's `.bss`:

- **Handle table** (`0x4040c0`, 32 slots × 16 bytes): `[ptr][type][active]`, populated by "Allocate device". Each device is a `calloc(1, 0x100)` chunk with an 8-byte magic (`"PHDEVICE"`), an 8-byte **refcount** (init 1), a size field, and an obfuscated self-pointer.
- **Session table** (`0x404080`, 8 slots × 8 bytes): raw pointers, populated by "Create session". Each session is also a `calloc(1, 0x100)` chunk, holding a magic, a uid, a **privilege flag** (must equal `0x1337133713371337` to unlock "Request privileged data" and read `flag.txt`), a "role" value, and two 64-bit integrity checksums.

## Bug #1 — refcount never bumped on duplicate

"Duplicate handle" copies a handle's device pointer into a second free slot — but never touches the device's own refcount field. "Release handle" decrements that refcount and only calls `free()` once it hits zero. So:

1. Allocate a device → handle _A_ (refcount = 1).
2. Duplicate _A_ → handle _B_ (same pointer, refcount **still** 1).
3. Release _A_ → refcount 1→0 → the chunk is actually `free()`d, and slot _A_ is cleared — but slot _B_ is left untouched, still marked "active" and still pointing at the now-freed chunk.

Handle _B_ is a classic **use-after-free** handle.

## Bug #2 — calloc() doesn't check tcache (but does check fastbins)

The natural next step is to reallocate something the same size (`calloc(1, 0x100)`, used identically by both "Allocate device" and "Create session") and let it land on the freed chunk. Tracing calloc/ free with an `LD_PRELOAD` shim showed this glibc's `calloc()` never serves from **tcache** — a single freed chunk is invisible to the very next `calloc()` call, even though a plain `malloc()`/`free()`/`malloc()` pair _does_ reuse the chunk immediately. This is a known hardening change in recent glibc specifically aimed at preventing this style of UAF-via-calloc bug.

Tcache's per-size-class capacity is 7, though — additional frees **overflow into the fastbins**, which `calloc()` _does_ consult. So:

- Allocate 7 "filler" devices and release all 7 → fills the tcache bin.
- Allocate one more device (the real target) and duplicate it before releasing → dangling handle _B_ as above.
- Release the target (the **8th** same-size free) → tcache is full, so this chunk overflows straight into the fastbins.
- "Create session" now calls `calloc(1, 0x100)` — walks fastbins first, finds our overflowed chunk, and hands it back. The new session now physically overlaps the memory handle _B_ still references.

Handle _B_'s "Read device" / "Write device" now read and write the live session object.

## Bug #3 — the privilege flag isn't checksum-protected (but is crypto-gated)

The session's privilege flag (offset `+0x10`) is compared directly to `0x1337133713371337` and is **not** an input to either integrity checksum — so it can be overwritten freely through the dangling handle without breaking anything else. But two 64-bit checksums still stand in the way:

```
checksum1 = rol(uid ^ cookie, 17) ^ raw_role ^ 0xa55aa55aa55aa55a
checksum2 = rol(raw_role, 11) ^ cookie ^ rol(uid + 0x5478547854785478, 29)
```

`cookie` is a secret 64-bit value seeded from `/dev/urandom` at startup and stored in `.bss`. Comparing the disassembly of session _creation_ against session _verification_ showed `checksum1` uses an identical formula in both places — but `checksum2`'s creation-time version uses a different embedded constant, meaning it can **never** validate for an untouched, legitimately created session.

The fix falls out of the algebra: since `uid` is public (`1000 + session index`) and `raw_role` and `checksum1` can be read straight out of the overlapping memory via the dangling handle, `checksum1`'s formula can be inverted to recover the cookie:

```
cookie = uid ^ ror(checksum1 ^ raw_role ^ 0xa55aa55aa55aa55a, 17)
```

With the cookie known, `checksum2` can be recomputed exactly the way the verification code expects, and both it and the privilege flag can be written back through the dangling handle.

## Exploit sequence

1. Allocate 7 filler devices, release all 7 (fills tcache).
2. Allocate a target device, duplicate it (dangling twin handle).
3. Release the target (8th free → overflow into fastbin).
4. Create a session (reuses the overflowed chunk).
5. Read `uid`, `raw_role`, `checksum1` through the dangling handle.
6. Recover the cookie from `checksum1`'s formula.
7. Recompute `checksum2` and write it, plus the privilege flag (`0x1337133713371337`), through the dangling handle.
8. Request privileged data on that session → passes every check → `flag.txt` is read and returned.

## Verification

Tested first locally against the unmodified binary with a dummy `flag.txt`, then run against the real service:

```
$ python3 exploit.py REMOTE
[+] Opening connection to 45.56.67.129 on port 51429: Done
[*] target device handle 7, dangling alias handle 8
[*] filled tcache and overflowed the target chunk into the fastbin
[*] session 0 now overlaps the freed device chunk
[*] leaked uid=1000 raw_role=0x5f2671b61c5ad5ae checksum1=0x3b32bcaca38eec9a checksum2=0x5592f8e0aaa5547e
[*] recovered cookie = 0x4e3760a734200eaf
[*] forged privilege flag and checksum2
BDSEC{ph4nt0m_h4ndl35_n3v3r_d13}
```

## Flag

```
BDSEC{ph4nt0m_h4ndl35_n3v3r_d13}
```

## Takeaways

- Reference counting bugs are easy to introduce anywhere an object can be aliased (`dup`-style primitives) — always check that every path that _creates_ an alias also updates whatever the _release_ path trusts.
- Modern glibc hardening (calloc bypassing tcache) closes the most "obvious" version of a UAF-via-reallocation bug, but doesn't close it entirely — fastbin overflow past tcache's capacity is a simple, reliable way around it when you can free the same size repeatedly.
- Integrity checksums are only as strong as the assumption that every field they _don't_ cover is unimportant. Here, the one field that actually gated privilege (the flag itself) was deliberately left outside the checksum's scope — but the checksum system still hid a secret worth recovering (the cookie), which turned "just overwrite a flag" into a small crypto puzzle layered on top of the memory bug.
---

_Obito Uchiha — Team AKATSUKI_
