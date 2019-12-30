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
Back to shellcode argument, today we will speak about alphanumeric shellcode. This arguemnt was suggested to me from @nahualito, some weeks ago and i have to admint it took me crazy sometimes but it was also a lot fun. The scope of the task is to create a shellcode completely of alphanumeric characters. The reason of this madness is because
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

What can we directly deduct of all this?

- NO "MOV" INSTRUCTIONS:
 => we need to find another way to manipulate our data.
- NO INTERESTING ARITHMETIC INSTRUCTIONS ("ADD","SUB",...):
 => we can only use DEC and INC.
 => we can't use INC with the EAX register.
- THE "XOR" INSTRUCTION:
 => we can use XOR with bytes and doublewords.
 => very interesting for basic crypto stuff. 
- "PUSH"/"POP"/"POPAD" INSTRUCTIONS:
 => we can push bytes and doublewords directly on the stack.
 => we can only use POP with the EAX,ECX and EDX registers.
 => it seems we're going to play again with the stack.
- THE "O16" OPERAND SIZE OVERRIDE:
 => we can also achieve 16 bits manipulations with this instruction
    prefix.
- "JMP" AND "CMP" INSTRUCTIONS:
 => we can realize some comparisons.
 => we can't directly use constant values with CMP.


Not so much ah?! Ah and obviuosly don't forget that operands of these instructions (</r>, <imm8>,
<imm32>, <disp8> and <disp32>) must also remain alphanumeric. It may make our task once again more complicated...

## First alphanumeric instructions
No panic, we can obtain a shellcode with a little of fantasy.<br>
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
