---
layout: single
title: Win32 Shellcode Intro
date: 2019-11-10
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
Since now, we have talked about shellcoding on Linux. Now we move on a more jiucy target: Windows OS. Writing shellcode for Windows isn't linear and simple like Linux. First of all Windows doesn't has syscall but instead we must use kernel API to call functions for what we need to do. Second and most important the addresses of this function are not static and may change from version to version of Windows kernel release.
There are a lot of well done and very helpfull dcoumentation out there, covering the Win32 shellcode. Let me list some of this documentation from which we took inspiration and from we took some pieces of code to understand how to make some shellcodes:
- [This amazing book](https://nostarch.com/malware) help me a lot understand how Win32 kernel API works
- [The amazing h0mbre blog](https://h0mbre.github.io/Babys-First-Shellcode/) 
- [Introduction to Windows Shellcode Development – Part 3](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/) by [@NytroRST](https://twitter.com/NytroRST/)
- [Windows Shellcoding x86 – Hunting Kernel32.dll – Part 1](https://0xdarkvortex.dev/index.php/2019/03/18/windows-shellcoding-x86-hunting-kernel32-dll-part-1/) by [@NinjaParanoid](https://twitter.com/NinjaParanoid)
- [Shellcoding for Linux and Windows Tutorial](http://www.vividmachines.com/shellcode/shellcode.html#ws) by [Steve Hanna](https://twitter.com/lestevehanna)
- [A good paper book](http://hick.org/code/skape/papers/win32-shellcode.pdf)
- [Windows x86 MessageBox shellcode](https://marcosvalle.github.io/re/exploit/2019/01/19/messagebox-shellcode.html) by [MValle](https://twitter.com/_mvalle_) 

A big thank to all them for their fantastic works.<br>
Now let's start from theory. As said we can't work directly with syscall, but we have to find the functions addresses loaded in memory. To find the addresses we first find the "handbook" that contains the pointers to some basic functions which are necessary to find what we need. There are basically 2 methods to find this addresses:

- Use the [arwin tool](http://www.vividmachines.com/shellcode/arwin.c) by Steve Hanna that find the static functions addresses for you
- Raise the chain and find all the dlls and functions by hand<br>

We know what you thinking, the arwin tool seems to be the best choice and in some cases this is true, mostly when we need to develop shellcode fast and small but you have also to know that using arwin tool has its downsides. First using static addresses means that a shellcode maybe works for a OS version but not for another and secondly it means that you had alrady an access to the machine you want to compromise and that's last point isn't always true. So in our case we choosed to raise the chain and find the addresses by hand.<br>
Accordingly with the documentation, the API are exported through dlls that are mapped in the process during its execution. The "handbook" and the only one dll that surely will be mapped in the process is called ```kernel32.dll```, this is the first element that we need to find. Accordingly with the paper book there are 3 methods to find the ```kernel32.dll```  address, PEB, SEH and TOPSTACK methods, but we managed to apply only the PEB method so we discuss only this one.

### PEB
The OS allocates a structure for every runnig process, the first structure is the TEB, accessible from the FS segment register, at offset 0x30 within TEB is the pointer to the PEB ```fs:[0x30]```. The PEB structure holds infos about heaps, binary image infos and most important, 3 linked lists regarding loaded modules that have been mapped in the process space. So starting from here we can find the ```kernel32.dll``` address, rising the modules addresses that are store always with fixed offsets.
As said at offset ```0xc``` within the PEB is the pointer to the ```PEB_LDR_DATA``` structure, which contains 3 doubly linked lists of ```LDR_DATA_TABLE``` structures, one for each loaded module. The DllBase field in the ```kernel32.dll``` entry is the value we're seeking. So the steps are here listed:

1. ```PEB``` is located at ```0x3``` From File Segment register
2. ```LDR``` (PEB structure) is located at ```PEB + 0xc``` offset
3. ```InMemoryOrderModuleList``` is the order in which the modules get stored in memory and is located at ```LDR + 0x14``` offset
4. 1st module is the exe address itself
5. 2nd module is the ```ntdll.dll``` address
6. 3rd module is the ```kernel32.dll``` address at offset ```LDR + 0x10```

The 3rd module is what we are seeking but we need to know one last thing. Everytime a dll is loaded, the address gets stored at the offset of DllBase wich is ```0x18```. Our start address of linked list will be stored in the offset of InMemoeryOrderLinks which is at offset ```0x08```. Thus the offset difference would be:<br>
<br>
```DllBase - InMemoryOrderLinks = 0x18 - 0x08 = 0x10```

## From theory to practice
Move on on some assembly code to view things in a "more simple" perspective. Take note that the addresses used in this chunk of code are fictitious and the debug commands are from WinDbg.

```nasm
global _start


section .text
_start: 

	;   PEB is located at offset 0x030 from the main the File Segment register
	;   LDR is located at offset PEB + 0x00C
	;   InMemoryOrderModuleList is located at offset LDR + 0x014
	;   First module Entry is the exe itself
	;   Second module Entry is ntdll.dll
	;   Third module Entry is kernel32.dll
	;   Fourth module Entry is Kernelbase.dll
	;----------------------------------------------------------------------
	; !peb
	; Ldr                       		76e77880
	;----------------------------------------------------------------------
	; PEB
	; dt nt!_TEB
	; +0x030 ProcessEnvironmentBlock 	: Ptr32 _PEB
	;----------------------------------------------------------------------
	; LDR
	; dt nt!_PEB
	; +0x00c Ldr              			: Ptr32 _PEB_LDR_DATA
	;----------------------------------------------------------------------
	; InMemoryOrderModuleList
	; Now find the start address of the InMemoryOrderModuleList using the LDR address
	; dt nt!_PEB_LDR_DATA 76e77880-8
	; +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x2b1990 - 0x2b2d08 ]
	;-----------------------------------------------------------------------
	; InMemoryOrderModuleList isn't a _LIST_ENTRY type but is a LDR_DATA_TABLE_ENTRY
	; accordingly with:
	; https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
	; 1st module
	; dt nt!_LDR_DATA_TABLE_ENTRY 0x2b1990-8
	; BaseDllName      : _UNICODE_STRING "C:\Users\workshop\Desktop\nc.exe"
	; +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x2b1a20 - 0x76e7788c ]
	;-----------------------------------------------------------------------
	; 2nd module
	; dt nt!_LDR_DATA_TABLE_ENTRY 0x2b1a20-8
	; BaseDllName      : _UNICODE_STRING "C:\Windows\SYSTEM32\ntdll.dll"
	; +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x2b1d48 - 0x2b1990 ]
	;-----------------------------------------------------------------------
	; 3rd module
	; dt nt!_LDR_DATA_TABLE_ENTRY 0x2b1d48-8
	; BaseDllName      : _UNICODE_STRING "C:\Windows\system32\kernel32.dll"
	; +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x2b1e60 - 0x2b1a20 ]
	;-----------------------------------------------------------------------
	; 4th module
	; dt nt!_LDR_DATA_TABLE_ENTRY 0x2b1e60-8
	; BaseDllName      : _UNICODE_STRING "C:\Windows\system32\KERNELBASE.dll"
	; +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x2b2710 - 0x2b1d48 ]
	;-----------------------------------------------------------------------
	; Our main area of interest for now is which is Kernel32.dll. Every time you load a DLL, 
	; the address gets stored at the offset of DllBase which is 0x18. 
	; Our Start address of Linked Lists will be stored in the offset of 
	; InMemoryOrderLinks which is 0x08. 
	; Thus the offset difference would be DllBase – InMemoryOrderLinks = 0x18 – 0x08 = 0x10. 
	; Hence, the offset of Kernel32.dll would be LDR + 0x10


	; raise the chain since we load the kernel32.dll address in eax
	xor ecx, ecx
	mul ecx
	mov eax, [fs:ecx + 0x030]	; PEB loaded in eax
	mov eax, [eax + 0x00c]		; LDR loaded in eax
	mov eax, [eax + 0x014]		; InMemoryOrderModuleList loaded in eax
	mov eax, [eax]              ; program.exe address loaded in eax (1st module)
	mov eax, [eax]              ; ntdll.dll address loaded (2nd module)
	mov eax, [eax + 0x10]		; kernel32.dll address loaded (3rd module)
```
With this assembly code we can find the kernel32.dll address and store it in EAX register, so compile it and execute it in Immunity Debugger

```bash
root@root:# cat compile_windows.sh 
#!/bin/bash

echo "[+] Assembling with NASM"
nasm -f win32 -o $1.o $1.nasm

echo "[+] Linking..."
ld -m i386pe -o $1.exe $1.o

echo "[+] Done."
root@root:# ./compile_windows.sh getkernel32
[+] Assembling with NASM
[+] Linking...
[+] Done.
```
![](/assets/images/windows/x86/getkernel_0.gif)<br>

Once we found the base address for kernel32.dll , we must parse it to find exported symbols. As with finding the location of kernel32.dll, this process involves following several structures in memory. PE files use relative virtual addresses (RVAs) when defining locations within a file. These addresses can be thought of as offsets within the PE image in memory, so the PE image base address must be added to each RVA to turn it into a valid pointer. The export data is stored in IMAGE_EXPORT_DIRECTORY . An RVA to this is stored in the array of IMAGE_DATA_DIRECTORY structures at the end of the IMAGE_OPTIONAL_HEADER . The location of the IMAGE_DATA_DIRECTORY array depends on whether the PE file is for a 32-bit application or a 64-bit application. Typical shellcode assumes it is running on a 32-bit platform, so it knows at compile time that the correct offset from the PE signature to the directory array is as follows:<br>

```sizeof(PE_Signature) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER) = 120 bytes```

```AddressOfFunctions``` is an array of RVAs that points to the actual export functions. It is indexed by an export ordinal (an alternative way of finding an exported symbol). The shellcode needs to map the export name to the ordinal in order to use this array, and it does so using the ```AddressOfNames``` and ```AddressOfNameOrdinals``` arrays. These two arrays exist in parallel. They have the same number of entries, and equivalent indices into these arrays are directly related. ```AddressOfNames``` is an array of 32-bit RVAs that point to the strings of symbol names. ```AddressOfNameOrdinals``` is an array of 16-bit ordinals. For a given index idx into these arrays, the symbol at ```AddressOfNames```[idx] has the export ordinal value at ```AddressOfNameOrdinals[idx]```. The ```AddressOfNames``` array is sorted alphabetically so that a binary search can quickly find a specific string, though most shellcode simply performs a linear search starting at the beginning of the array. To find the export address of a symbol, follow these steps:

1. The ```AddressOfNames``` array is sorted alphabetically so that a binary search can quickly find a specific string, though most shellcode simply performs a linear search starting at the at each char* entry, and perform a string comparison against the desired symbol until a match is found. Call this index into ```AddressOfNames``` iName
2. Index into the ```AddressOfNameOrdinals``` array using iName . The value retrieved is the value iOrdinal
3. Use iOrdinal to index into the AddressOfFunctions array. The value retrieved is the RVA of the exported symbol. Return this value to the requester.

The MS-DOS header is ```0x40``` bytes and the last 4 bytes are the ```e_lfanew``` pointer. So from base we have to add 60 bytes (```0x3c```) to point at the ```e_lfanew``` pointer. At offset ```0x78``` of the PE header we can find the "Data Directory" for the exports.

```0x78 = 120 bytes = sizeof(PE_Signature) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER)```

The export data is stored in ```IMAGE_EXPORT_DIRECTORY``` where we can find the offset of ```AddressOfNames``` at offset ```0x20``` 

```nasm

getAddressofName:
	mov edx, [ebx + 0x3c]		; load e_lfanew address in ebx
	add edx, ebx				
	mov edx, [edx + 0x78]		; load data directory
	add edx, ebx
	mov esi, [edx + 0x20]		; load "address of name"
	add esi, ebx
	xor ecx, ecx

	; ESI = RVAs
```
