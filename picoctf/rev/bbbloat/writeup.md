# bbbloat

## Summary

This challenge provides a stripped ELF 64-bit binary that prompts the user for a "favorite number." The goal is to reverse engineer the binary to find the expected input, which triggers a deobfuscation that decodes and prints the flag. The binary uses obfuscation to prevent the flag from appearing as a plaintext string, but the comparison value and the obfuscated flag data are both recoverable through static analysis in Ghidra.

**Artifacts:**
- `bbbloat`: stripped ELF 64-bit position-independent executable (PIE)

**Category:** Reverse Engineering  
**Tools used:** `file`, `strings`, `strace`, `ltrace`, Ghidra, Python3

---

## Context

The challenge provides a single binary file called `bbbloat`. Before doing anything else, the first step is always to understand what kind of file you are dealing with.

### Step 1 — Identify the file type with `file`

The `file` command reads the bytes at the start of a file and tells you what it actually is, regardless of the filename or extension. This is important in CTFs because files are sometimes mislabeled or have no extension at all.

```
$ file bbbloat
bbbloat: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

This means:

- **ELF**: Executable and Linkable Format — the standard binary format for Linux executables. This tells us it's a Linux binary, not a Windows `.exe` or a macOS Mach-O.
- **64-bit**: The binary was compiled for a 64-bit architecture (x86-64), meaning it uses 64-bit registers and memory addresses.
- **LSB**: Least Significant Byte first — i.e., little-endian byte ordering. This is standard for x86/x86-64.
- **pie executable**: Position Independent Executable. The binary is compiled so it can be loaded at any memory address. The OS will randomize the base address each run via ASLR (Address Space Layout Randomization). This makes certain exploit techniques harder but doesn't affect our approach here since we're doing static analysis.
- **dynamically linked**: The binary relies on shared libraries (like `libc`) that are loaded at runtime rather than being compiled into the binary itself. This means calls to functions like `printf` and `scanf` go through the Procedure Linkage Table (PLT).
- **stripped**: Debug symbols have been removed. Normally, a compiled binary keeps a symbol table mapping function names like `main` to their addresses. Stripping removes this, so a disassembler like Ghidra will label functions generically as `FUN_00101249` instead of `main`. This is a deliberate obfuscation step.

### Step 2 — Run the binary

Then I rain, the binary to understand what it does at face value:

```
$ chmod +x bbbloat    # make sure it's executable
$ ./bbbloat
What's my favorite number?
42
Sorry, that's not it!
```

We can see the program:
1. Prints a prompt asking for a number
2. Reads a number from stdin
3. Checks if it matches some expected value
4. Prints a failure message and exits if wrong

The goal is clear: find the number it expects.

### Step 3 — Check for plaintext strings with `strings`

I ran the `strings` command scans which scans a binary file and prints any sequence of printable ASCII characters above a minimum length (default 4). 
```
$ strings bbbloat
/lib64/ld-linux-x86-64.so.2
...
__libc_start_main
...
What's my favorite number?
Sorry, that's not it!
...
```

We can see the prompt and failure strings, but no flag and no obvious password or number. This tells us the flag and the expected input are either computed at runtime or stored in a non-obvious form. 
---

## Dynamic Analysis

I then tried `ltrace` and `strace`.

### ltrace — Library Call Tracer

`ltrace` intercepts and logs every call a program makes to shared library functions. This is useful because many programs compare passwords or secrets using library calls like `strcmp("user_input", "secret")` — and `ltrace` would show both arguments.

```
$ ltrace ./bbbloat
What's my favorite number?
42
Sorry, that's not it!
+++ exited (status 0) +++
```

`ltrace` produces almost no output here. The program runs and exits, but no library calls with interesting arguments are logged. This tells us the comparison is **not** done through a function like `strcmp` — it's handled inline in the binary's own code, likely as a direct integer comparison (`==`). This means `ltrace` won't give us the answer.

### strace — System Call Tracer

`strace` operates one level lower than `ltrace`. Instead of library calls, it intercepts raw system calls — the interface between a program and the Linux kernel. Common system calls include `read` (reading input), `write` (printing output), `open` (opening files), and `mmap` (mapping memory).

```
$ strace ./bbbloat
execve("./bbbloat", ["./bbbloat"], 0x7ffd... /* 23 vars */) = 0
...
mmap(NULL, 8192, PROT_READ|PROT_WRITE, ...) = 0x7f...
...
write(1, "What's my favorite number?\n", 27) = 27
read(0, 42
"42\n", 1024)                           = 3
write(1, "Sorry, that's not it!\n", 22)  = 22
exit_group(0)                           = ?
```

Breaking down the key lines:

- `write(1, "What's my favorite number?\n", 27)` — writes 27 bytes to file descriptor 1 (stdout), which is the prompt we see
- `read(0, "42\n", 1024)` — reads from file descriptor 0 (stdin); we typed `42` and hit enter
- `write(1, "Sorry, that's not it!\n", 22)` — writes the failure message to stdout
- `exit_group(0)` — program exits with status 0

`strace` confirms the control flow but does not reveal the expected number. The comparison value never touches a system call — it's purely internal to the program's logic. 

---

## Static Analysis with Ghidra

Since dynamic analysis didn't surface the answer, I opened the binary in Ghidra. Ghidra disassembles the binary into assembly instructions and then **decompiles** them into readable C-like pseudocode.


I imported `bbbloat` into Ghidra and viewed it in the **CodeBrowser**.

### Finding main via Defined Strings

Since the binary is stripped, I couldn't just look for a function named `main`. So I looked for **Defined Strings**, where I found:

```
"What's my favorite number?"
```
### Decompiled pseudocode — main

With the function renamed, the decompiler pane shows something like this (variable names cleaned up for clarity):

```c
void main(void) {
    char *__s;
    int local_48;
    undefined8 local_38;
    undefined8 local_30;
    undefined8 local_28;
    undefined8 local_20;
    long local_10;

    // Build obfuscated flag byte by byte on the stack
    local
    local_38 = 0x4c75257240343a41;
    local_30 = 0x3062396630664634;
    local_28 = 0x65623066635f3d33;
    local_20 = 0x4e326560623535;

    printf("What\'s my favorite number?\n");
    __isoc99_scanf();
    if (local_48 == 0x86187) {
        __s = (char *)FUN_00101249(0,&local_38);
        fputs(__s,stdout) ;
        putchar(10);
        free(__s);
    }
    else {
        puts("Sorry, that\'s not it!");
    }
    return;
}
```

Let's break down what we see:

**The stack variables (`local_38` through `local_30`)** are large hex constants being loaded into local variables. At first glance these look like arbitrary numbers, but they are actually the flag stored as raw bytes packed into 8-byte chunks. The decompiler doesn't know to interpret them as a string — it just shows them as integers. 

**The `scanf("%d", &user_input)` call** reads a decimal integer from stdin and stores it in `user_input`. The `%d` format specifier confirms the program expects a base-10 integer — which is why entering hex values directly won't work.

**The comparison `user_input == 0x86187`** is the key check. This is a hardcoded constant. If our input matches this value, we win. There is no hashing, no encryption, no network call — just a direct integer equality check.

**If the check passes**, the function `deobfuscate_and_print` is called with a pointer to `local_38`.

### Converting the comparison constant

We need to enter `0x86187` as a decimal integer since `scanf` reads `%d`:

```
$ python3 -c "print(0x86187)"
549255
```
---

## Obfuscation / Deobfuscation Breakdown

### How the flag is hidden

The flag is stored as a series of 8-byte integer constants in the function body:

```
local_38 = 0x4c75257240343a41;
local_30 = 0x3062396630664634;
...
```

These the flag's bytes packed together, with each byte XOR'd with the key `0x13` to disguise them. Because they are loaded as integer literals rather than a contiguous string, they do not show up in `strings` output. The flag only exists in decoded form in memory during the brief moment after the correct input is entered.

### The deobfuscation function

Double-clicking `deobfuscate_and_print` in the decompiler takes us to:

```c
void deobfuscate_and_print(char *buf) {
    size_t len;
    int i;

    len = strlen(buf);
    i = 0;
    while (i < (int)len) {
        putchar((int)(char)(buf[i] ^ 0x13));
        i = i + 1;
    }
    putchar(10);   // print newline (ASCII 10 = '\n')
    return;
}
```

This function:
1. Takes a pointer to the obfuscated buffer
2. Finds its length with `strlen`
3. Loops over every byte
4. XORs each byte with `0x13` and prints the result with `putchar`

**Why XOR?** XOR is a bitwise operation that is its own inverse: if `A ^ K = B`, then `B ^ K = A`. This means the same key and operation both encodes and decodes. It's the simplest possible symmetric cipher, and here the key (`0x13`) is hardcoded in the binary, making it trivially reversible once you know it.


**Why does this defeat `strings`?** The `strings` tool looks for runs of consecutive printable ASCII bytes. Because the flag is XOR'd with `0x13`, most bytes are shifted outside the printable range (roughly `0x20`–`0x7e`), so `strings` doesn't recognize them as text. Additionally, the bytes are packed into 8-byte integer chunks rather than a C string, which further prevents `strings` from finding them.

---

## Exploitation

### Step 1 — Convert the constant

```
$ python3 -c "print(0x86187)"
549255
```

### Step 2 — Run the binary with the correct input

```
$ ./bbbloat
What's my favorite number?
549255
picoCTF{...}
```

The deobfuscation function runs, XORs each stored byte with `0x13`, and prints the decoded flag.


### Step 3 — Extract just the flag value

```
$ echo "549255" | ./bbbloat | grep -oP 'picoCTF\{.*?\}'
picoCTF{...}
```
`picoCTF{cu7_7h3_bl047_36dd316a}`

---

## Exploit Primitive Summary

| Primitive | Detail |
|-----------|--------|
| Binary type | Stripped ELF 64-bit PIE — no symbols, base address randomized |
| Comparison mechanism | Direct integer equality: `user_input == 0x86187` (549255 decimal) |
| Flag storage | Bytes packed into stack-allocated integer literals, never a contiguous string |
| Obfuscation method | Single-byte XOR with static key `0x13` |
| Deobfuscation trigger | Correct input passes the `if` check, calling the XOR decode loop |
| Relevant mitigations | PIE present but irrelevant; no canary; no anti-debug |

---

## Remediation

The fundamental issue is that both the secret input and the encoded flag are hardcoded into the binary. No matter how the flag is obfuscated, an attacker with Ghidra can always find and reverse it. Mitigations that would raise the bar:

- **Server-side validation**: Instead of embedding the expected value locally, send the input to a remote server for checking. The binary never contains the answer, so there is nothing to extract through static analysis.
- **Cryptographic hash comparison**: Rather than comparing `input == 0x86187`, compare `sha256(input) == <stored_digest>`. A hash cannot be inverted — an attacker would need to brute force or recognize the constant without being able to simply read it out of the decompiler.
- **Stronger obfuscation**: A single-byte XOR with a static key is the weakest possible cipher. A keyed stream cipher, a proper block cipher, or even a multi-byte XOR with a changing key would significantly slow down manual reversal.
- **Anti-analysis techniques**: Techniques like binary packing, `ptrace`-based anti-debugging checks, or self-modifying code would slow down Ghidra analysis and dynamic tracing, though none are insurmountable.

For a CTF challenge, the difficulty is intentionally calibrated — the obfuscation is just enough to require a real disassembler rather than `strings`, making it an appropriate introduction to Ghidra and basic reverse engineering.