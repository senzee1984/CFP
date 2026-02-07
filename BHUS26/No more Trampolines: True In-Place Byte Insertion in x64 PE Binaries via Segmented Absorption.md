

# Motivation: From Personal Frustration to a Public Gap

## The Obsession: Why I Couldn't Let Go of a Few Missing Bytes
When I first entered the world of binary security, IDA was my scalpel. I'd patch simple programs—flip a jz to jnz, bypass a license check, bend the logic to my will. I didn't fully understand PE structures yet, but I could make things work.

Every time I opened the "Patch Program" menu, I saw "Change byte." And every time, the same question nagged at me: Where is "Insert byte"?

With insertion, I could do so much more than flip branches. I could inject instrumentation, add checks, expand functionality—not just negate what was already there.

<img width="685" height="317" alt="image" src="https://github.com/user-attachments/assets/9d21ad41-57ad-41f2-a722-961383711444" />

As I learned more about PE internals, I understood why the option didn't exist. Insert a single byte, and everything downstream shifts. Relative jumps break. Call targets corrupt. The executable dies. But I still thought: Surely there's an algorithm to fix all that. Why hasn't anyone built it?

Years passed. My understanding deepened. I came to appreciate the true complexity—the relocation tables, the exception metadata, the jump tables hiding in data sections. I understood why IDA, Ghidra, and every other tool sidesteps this problem. But I never stopped wishing someone would solve it.


## The Byte Budget Problem
During reverse engineering, sometimes you just need to borrow a few bytes. I'm not greedy—just a handful! Yes, there are workarounds: redirect execution to a new section, hunt for code caves, set up trampolines. But these feel like overkill when all you need is a few bytes of breathing room. 

Let me illustrate with a real scenario. I enjoy reversing game programs—not for any specific goal, just as a playground to sharpen my skills. I like to probe limitations, remove restrictions, see what bends and what breaks.

Consider the following (fictionalized) game‑server logic: each player account is assigned a unique ID at login. My goal was to force the server into a single‑player mode for demo or trial use, relying solely on patching to achieve it. With source code, it is trivial by just hardcoding the ID assignment, and every subsequent player collides with the first. But in assembly?

```asm
8b  de           MOV        EBX ,ESI                            // EBX and ESI both stores the non-zero unique ID
ff  15  50       CALL       dword ptr [->KERNEL32.DLL::LeaveCriticalSectio   = 003cd72c
90  72  00
8b  c6           MOV        EAX ,ESI
89  75  f0       MOV        dword ptr [EBP  + -0x10 ],ESI
35  ef  be       XOR        EAX ,0xdeadbeef
ad  de

<...Skip Hash Compution...>
b9  78  2f       MOV        ECX, OFFSET UNK_7D2F78                       // Value at RVA 0x7d2f78 is passed to ECX
7d  00
50               PUSH       EAX
<...SNIP...>
8b 7d ec         MOV        EDI ,dword ptr [EBP  + -0x14 ]
8d  47  04       LEA        EAX ,[EDI  + 0x4 ]
87  18           XCHG       dword ptr [EAX ],EBX                // pInstance->SetUniqueID(uniqueId);
8d  45  e8       LEA        EAX ,[EBP  + -0x18 ]
89  75  e8       MOV        dword ptr [EBP  + -0x18 ],ESI
50               PUSH       EAX
8d  45  d8       LEA        EAX ,[EBP  + -0x28 ]
89  7d  ec       MOV        dword ptr [EBP  + -0x14 ],EDI
50               PUSH       EAX
b9  78  2f       MOV        this ,0x7d2f78
7d  00
e8  75  1f       CALL       std::_Hash<>::emplace<>             //m_entityMap.insert(EntityMap::value_type(uniqueId, pInstance));
00  00
```

At the start of this code snippet, both EBX and ESI hold the unique ID. When execution reaches the XCHG instruction, EAX points to the memory location where the ID will be written (pInstance->uniqueId). If we force this value to a constant, every subsequent player would collide with the first—effectively restricting the game to single-player mode. The question is: how do we accomplish this using only patching?

One might consider replacing `MOV EBX, ESI` with `XOR EBX, EBX`—the byte count remains identical. But `zero` is a reserved guard value; the system rejects it as invalid. This seemingly clever shortcut leads nowhere.

In-place byte insertion would make the task trivial: inject `MOV EBX, 1` right before the XCHG instruction, and we're done. But no tool offers this capability. So I had to find another way—patching only, no additional bytes. Through debugging, I eventually discovered a workable solution. The key observation: ECX holds a constant value every time execution reaches this point. Regardless of what happens elsewhere, it never changes during runtime. This consistency is all we need:

```asm
89 08          mov    [eax], ecx                 //xchg    ebx, [eax]
8d 45 e8       lea     eax, [ebp+var_18]
89 4d e8       mov     [ebp+var_18], ecx         //mov     [ebp+var_18], esi
```

EAX contains the address of the ID field (EDI + 4). By replacing the original XCHG with `MOV [EAX], ECX`, we directly write a fixed value to that field. Because `[EBP-18h]` is used as the key for `hash_map::insert()`, we also substitute `MOV [EBP-18h], ESI` with `MOV [EBP-18h], ECX` to keep the stored ID and the map key aligned. EBX still holds the original unique ID, but since it’s never referenced afterward, it has no impact on the patch.

That said, this solution exists only because of a fortunate coincidence. The constant value in ECX was completely opaque to static analysis; I discovered it only by stepping through the code at runtime. Not every target provides such a gift. Registers don’t always contain something useful, and sometimes there simply isn’t a hidden trick waiting to be exploited—pure patching hits a hard limit.

A few bytes of in‑place insertion would have solved the problem instantly. Without that option, I ended up spending hours debugging toward a solution that easily might not have existed.

## The Echo Chamber
I'm not alone in wanting this. Forum posts stretching back years ask the same question:

<img width="926" height="678" alt="image" src="https://github.com/user-attachments/assets/d6068ede-10b8-4133-8197-9daf48d38bd2" />



<img width="924" height="801" alt="image" src="https://github.com/user-attachments/assets/9c7cef98-a71c-437d-9a56-d265d54cd9fc" />


According to the second author, in his situation the in‑place insertion worked because there were unused bytes at the end of the function and the change was small. However, as the number of insertions grows or the target address differs, this won’t always hold true, and the process becomes increasingly difficult and complex.

## "Everyone avoids the problem" — a gap in the ecosystem

We saw the demands—but what about the answers? The replies are overwhelmingly consistent: add a new section, or hunt for a code cave, redirect execution there, then jump back.

<img width="913" height="650" alt="image" src="https://github.com/user-attachments/assets/88500564-dc0b-4c67-97d3-299a0d0bbe75" />


<img width="957" height="600" alt="image" src="https://github.com/user-attachments/assets/b410c405-b28e-4dfa-9813-3cfc997e4791" />


<img width="955" height="332" alt="image" src="https://github.com/user-attachments/assets/2b43361d-84ba-4c71-ace7-5dd339a4e27f" />


Yes, these are solutions. But they're not the solution we actually want. They're workarounds—detours around the real problem. The community has collectively shrugged and accepted that in-place byte insertion is "too complex," "too fragile," "not worth the effort."

But is it really impossible? Or has everyone simply avoided it for so long that it became an unquestioned assumption?

Before we challenge that assumption, let's examine what these workarounds actually cost us.


# Existing Binary Patching Bottleneck
Before diving deep into in-place insertion, let's revisit the existing approaches—their advantages and their bottlenecks.

## New Section Injection: A Sledgehammer for a Nail
The most widely used approach is new section injection. The process works as follows: add a new executable section to the PE file, modify the header metadata accordingly, and place a redirection instruction (trampoline) at the target location pointing to the new section. Inside the new section, we must first restore the original instructions that were overwritten by the trampoline, then add our own code, and finally jump back to the instruction immediately following the trampoline.

Let's use Process Monitor from the Sysinternals suite as an example. We will insert new instructions at 0x1400a310b, inside the main function.

<img width="1178" height="656" alt="image" src="https://github.com/user-attachments/assets/1afec6ac-5c74-4325-9c4f-8fadfa78db7a" />

I wrote a script to automate this process. After adding the new section and placing the trampoline, let's inspect the result using PE Bear. Navigating to the target address, we can see the trampoline in place. The original MOV instruction occupied 7 bytes, so the trampoline consists of a 5-byte JMP instruction followed by 2 NOP bytes for padding.

<img width="1089" height="474" alt="image" src="https://github.com/user-attachments/assets/51ec86c5-de5d-4783-82c5-6b246c27c2ee" />

Following the redirection, we arrive at the new section. The first instruction here is the one that was replaced by the trampoline—it must be restored, otherwise the program logic would be corrupted. After that comes our inserted code (in this case, just a single NOP). Finally, a JMP instruction redirects execution back to the instruction immediately after the trampoline.

<img width="1112" height="332" alt="image" src="https://github.com/user-attachments/assets/e82f8b3e-26dc-4202-a115-fbb76a9d98df" />

As we can confirm, a new section has been added. Its characteristics match those of the .text section.

<img width="864" height="342" alt="image" src="https://github.com/user-attachments/assets/4895487b-9338-4df4-b9da-b2ebf8e29642" />

All we wanted was to insert 1 single byte. Yet the trampoline consumed 5+2 bytes, and the new section required 13 bytes. If the instruction at the insertion point were longer, the overhead would be even higher. And within the .text section, a short jump cannot cover the distance to the new section—so a near jump is mandatory. The minimum byte requirements are:

- Trampoline: 5+ bytes
- Replaced instruction (must be restored in new section): 5+ bytes
- Inserted code: 1+ byte
- Return jump: 5 bytes

A minimum of 16 bytes are required in total—just to insert a single byte.

So far, we have examined this method from the perspective of reverse engineering, where patching typically requires only a handful of bytes and detection is not a primary concern—reverse engineers usually work locally with disassemblers and debuggers, experimenting freely.

However, these techniques extend beyond reverse engineering. Offensive security practitioner can leverage the same approach to weaponize trusted executables by embedding shellcode, as illustrated in resources like [Art of Anti-Detection: PE Backdoor Manufacturing](https://pentest.blog/art-of-anti-detection-2-pe-backdoor-manufacturing/) and [Backdooring Portable Executables with Shellcode](https://www.ired.team/offensive-security/code-injection-process-injection/backdooring-portable-executables-pe-with-shellcode). The goal is to preserve normal program behavior while silently executing a malicious payload.

For payload development and delivery, however, detection becomes a real concern. A newly added section is an obvious indicator of tampering—a significant drawback when stealth matters. Code cave hunting fares slightly better, but as we'll see, it has its own limitations.

Finally, include an image to visually illustrate the steps involved.

<img width="1727" height="1234" alt="image" src="https://github.com/user-attachments/assets/de05f2c3-fe16-46d6-b467-7ff147d44ee5" />

## Code Cave Hunting: Working with Scraps
The code cave hunting approach is similar to adding a new section in terms of execution flow redirection. As we discussed, the new section method has obvious drawbacks—most notably, the newly added section is easily visible.

Code cave hunting relies on finding existing sequences of empty bytes scattered throughout the binary, ideally within the .text section—since this avoids any need to modify section characteristics. In .text sections of MSVC-compiled programs, empty bytes are typically found at the end of functions due to alignment padding. Additionally, it is rare to see a fully-utilized .text section; typically, a significant number of unused bytes exist at the tail of the section. However, it is uncommon to find substantial empty byte sequences in the middle of a function—certainly not enough for code cave purposes.

<img width="901" height="384" alt="image" src="https://github.com/user-attachments/assets/2d330ba5-8708-46b8-9d6d-0539461a1de3" />

We strongly prefer code caves located in the .text section when available. Other sections such as .data often contain many empty bytes as well, but they come with complications. First, they are not executable, so their characteristics must be modified—adding yet another detection artifact. Second, even if bytes appear unused during static analysis, some may hold values at runtime. Filtering out these false positives is troublesome and error-prone

Let's continue using Procmon64.exe as our example. My script selected a code cave within the .text section—exactly what we hoped for. The trampoline and inserted bytes are identical to those in the new section method.

<img width="1105" height="279" alt="image" src="https://github.com/user-attachments/assets/05a744bc-cd4a-440f-8cd1-f8df00af5cda" />

<img width="759" height="277" alt="image" src="https://github.com/user-attachments/assets/cb9ffa60-3084-4292-b09c-2e065859ff5d" />

Let's use the script to list available code caves in Process Monitor. First, we search across all sections—meaning any cave outside .text would require modification of section characteristics. As shown, we have multiple large code caves available. For reverse engineers, the change of characteristics is typically not a concern.

```pwershell
python .\BinaryScalpel.py -m 1 .\sysinternals\Procmon64.exe --list-caves  --cave-top 10
Code Caves Found (sorted by size, largest first) - Top 10:
----------------------------------------------------------------------
  RVA: 0x001F4DF7 (File: 0x1DDBF7)  Size:   2268  Section: .rsrc ← LARGEST
  RVA: 0x00170317 (File: 0x159117)  Size:   2073  Section: .rsrc
  RVA: 0x00173B2E (File: 0x15C92E)  Size:   2050  Section: .rsrc
  RVA: 0x001F6B90 (File: 0x1DF990)  Size:   1664  Section: .rsrc
  RVA: 0x0013E8A1 (File: 0x13C6A1)  Size:   1507  Section: .data
  RVA: 0x001F739F (File: 0x1E019F)  Size:   1008  Section: .rsrc
  RVA: 0x0017453F (File: 0x15D33F)  Size:    985  Section: .rsrc
  RVA: 0x00176596 (File: 0x15F396)  Size:    962  Section: .rsrc
  RVA: 0x001F8447 (File: 0x1E1247)  Size:    772  Section: .rsrc
  RVA: 0x001F80E4 (File: 0x1E0EE4)  Size:    724  Section: .rsrc

Showing: 10 caves
Largest cave: 2268 bytes in .rsrc
  → Maximum payload for Method 2: 2253 bytes (minus trampoline overhead)
Total available space (shown caves): 14013 bytes
```

However, if we restrict our search to the .text section for better stealth, options become limited. The largest cave is only 132 bytes. This should suffice for reverse engineers who simply want to insert a few bytes to flip some logic. But for offensive security practitioner, 132 bytes is hardly enough to accommodate meaningful shellcode. Consequently, for payload development and delivery, practitioners often resort to caves in other sections, as illustrated in articles like [Backdoor 101 - Part 2](https://captmeelo.com/exploitdev/2018/07/21/backdoor101-part2.html).


```powershell
python .\BinaryScalpel.py -m 1 .\sysinternals\Procmon64.exe --list-caves --cave-section .text --cave-top 10
Code Caves Found in .text (sorted by size, largest first) - Top 10:
----------------------------------------------------------------------
  RVA: 0x000F017C (File: 0x0EF57C)  Size:    132  Section: .text ← LARGEST
  RVA: 0x000D8F31 (File: 0x0D8331)  Size:     21  Section: .text
  RVA: 0x000E8EF2 (File: 0x0E82F2)  Size:     20  Section: .text
  RVA: 0x000E8ED3 (File: 0x0E82D3)  Size:     19  Section: .text
  RVA: 0x000B9574 (File: 0x0B8974)  Size:     18  Section: .text
  RVA: 0x000E8F14 (File: 0x0E8314)  Size:     18  Section: .text
  RVA: 0x000042EF (File: 0x0036EF)  Size:     17  Section: .text
  RVA: 0x0000C19F (File: 0x00B59F)  Size:     17  Section: .text
  RVA: 0x0000F69F (File: 0x00EA9F)  Size:     17  Section: .text
  RVA: 0x0000F6BF (File: 0x00EABF)  Size:     17  Section: .text

Showing: 10 caves
Largest cave: 132 bytes in .text
  → Maximum payload for Method 2: 117 bytes (minus trampoline overhead)
Total available space (shown caves): 296 bytes
```

This limitation has minimal impact on reverse engineers. But for offensive security practitioners, it presents a dilemma: pursue larger caves in data sections and accept the detectable characteristic modification, or stay within .text for stealth and struggle with size constraints.

Finally, include an image to visually illustrate the steps involved.

<img width="1549" height="1221" alt="image" src="https://github.com/user-attachments/assets/17a006e3-a927-4926-8665-8bc0d5366387" />

## Both: Overkill when you just need a few bytes

Finally, let's compare these two classic methods side by side. Both have their advantages and drawbacks—particularly for offensive security practitioners who must balance capability against stealth. And even for reverse engineers, both options feel like overkill when all you need is a few bytes.

|  | 	ADDING NEW SECTION | 	HUNTING FOR CODE CAVE | 
| --- | --- | --- |
| PE Header Modified? | 	Yes |	No |
| File Size Changed? |	Yes	| No |
| New Section Visible? |	Yes |	No|
| Detection Difficulty |	Trivial	| Medium |
| Space Limitation? |	No	| Yes|
| Always Available? |  	Yes |	No |
| Trampoline Required? |	Yes	 | Yes|
| Min Overhead | 	16+ bytes |	16+ bytes |
| Execution Permission |	RX for new section	|Unchanged for code cave in .TEXT; RWX for code cave in other sections |

Ultimately, it all comes down to the byte budget. Heaven, just lend me a few bytes—just a few!




# The Obvious Challenges Everyone Expects

Having reviewed the two classic approaches, we can now turn to the main topic: in‑place byte insertion. As the name implies, this technique inserts new bytes or instructions directly at a chosen address, causing all subsequent instructions to shift accordingly. For simplicity, we assume the end of the .text section contains sufficient unused bytes that the insertion won't push the section beyond its boundaries. In this basic model, every instruction after the insertion point simply shifts forward; we make no attempt to reuse stray free bytes within or between functions. This represents the most straightforward form of in‑place insertion, and more advanced strategies will be explored in later sections.

## Relative References: call, jmp, jcc, and RIP-relative — the obvious suspects
Even with a basic understanding of the PE format and x86‑64 assembly, several challenges become immediately apparent. The most significant involves updating relative offsets in control‑flow and addressing instructions—such as call, jmp, conditional branches (jz, jnz, etc.), and RIP‑relative memory operands (lea, mov [rip+offset]). An example will make this clearer.

The assembly code below is taken from Procmon64.exe, specifically a portion of its WinMain function that handles registry operations during startup. This real-world example demonstrates a function dense with RIP-relative addressing—exactly the kind of code that makes in-place insertion challenging.

```asm
; ==================== BEFORE INSERTION ====================
; Procmon64.exe WinMain function (partial)

.text:1400A3080  48 89 5C 24 10              mov     [rsp+10h], rbx
.text:1400A3085  55                          push    rbp
.text:1400A3086  56                          push    rsi
.text:1400A3087  57                          push    rdi
.text:1400A3088  41 54                       push    r12
.text:1400A308A  41 55                       push    r13
.text:1400A308C  41 56                       push    r14
.text:1400A308E  41 57                       push    r15
.text:1400A3090  48 8D AC 24 B0 B6 FF FF     lea     rbp, [rsp-4950h]
.text:1400A3098  B8 50 4A 00 00              mov     eax, 4A50h
.text:1400A309D  E8 CE 6A 01 00              call    __chkstk                     ; target = 1400B9B70, after the insertion point
.text:1400A30A2  48 2B E0                    sub     rsp, rax
.text:1400A30A5  48 8B 05 D4 BF 09 00        mov     rax, [rip+9BFD4h]            ; __security_cookie
.text:1400A30AC  48 33 C4                    xor     rax, rsp
.text:1400A30AF  48 89 85 40 49 00 00        mov     [rbp+4940h], rax             ; stack variable, no fix needed
.text:1400A30B6  44 89 4C 24 78              mov     [rsp+78h], r9d
.text:1400A30BB  4C 89 45 20                 mov     [rbp+20h], r8
.text:1400A30BF  48 8B F1                    mov     rsi, rcx
.text:1400A30C2  48 89 4D 98                 mov     [rbp-68h], rcx
.text:1400A30C6  33 DB                       xor     ebx, ebx
.text:1400A30C8  89 5D 64                    mov     [rbp+64h], ebx
.text:1400A30CB  89 9D 54 01 00 00           mov     [rbp+154h], ebx
.text:1400A30D1  33 D2                       xor     edx, edx
.text:1400A30D3  41 B8 14 01 00 00           mov     r8d, 114h
.text:1400A30D9  48 8D 8D 58 01 00 00        lea     rcx, [rbp+158h]              ; stack variable, no fix needed
.text:1400A30E0  E8 6B 5E 04 00              call    sub_1400E8F50                ; target = 1400E8F50, after the insertion point
.text:1400A30E5  C7 85 50 01 00 00 1C 01 00 00  mov  [rbp+150h], 11Ch
.text:1400A30EF  48 8D 45 38                 lea     rax, [rbp+38h]               ; stack variable
.text:1400A30F3  48 89 44 24 20              mov     [rsp+20h], rax
.text:1400A30F8  41 BD 01 00 00 00           mov     r13d, 1
.text:1400A30FE  45 8B CD                    mov     r9d, r13d                    
.text:1400A3101  45 33 C0                    xor     r8d, r8d                     
.text:1400A3104  48 8D 15 A5 BB 06 00        lea     rdx, [rip+6BBA5h]            ; "Software\Microsoft\Windows NT\CurrentVersion"
;------------------------------------------------------------------------------------------------------------------------------------
.text:1400A310B  48 C7 C1 02 00 00 80        mov     rcx, 0FFFFFFFF80000002h      ; Insertion point
.text:1400A3112  FF 15 A0 DF 04 00           call    [rip+4DFA0h]                 ; RegOpenKeyExW
.text:1400A3118  85 C0                       test    eax, eax
.text:1400A311A  75 3E                       jnz     short loc_1400A315A          ; target = 1400A315A
.text:1400A311C  C7 45 78 04 00 00 00        mov     dword ptr [rbp+78h], 4
.text:1400A3123  48 8D 45 78                 lea     rax, [rbp+78h]
.text:1400A3127  48 89 44 24 28              mov     [rsp+28h], rax
.text:1400A312C  48 8D 85 60 01 00 00        lea     rax, [rbp+160h]
.text:1400A3133  48 89 44 24 20              mov     [rsp+20h], rax
.text:1400A3138  4C 8D 4D 74                 lea     r9, [rbp+74h]
.text:1400A313C  45 33 C0                    xor     r8d, r8d                     ; 
.text:1400A313F  48 8D 15 CA BB 06 00        lea     rdx, [rip+6BBCAh]            ; "UBS"
.text:1400A3146  48 8B 4D 38                 mov     rcx, [rbp+38h]
.text:1400A314A  FF 15 60 DF 04 00           call    [rip+4DF60h]                 ; RegQueryValueExW
.text:1400A3150  48 8B 4D 38                 mov     rcx, [rbp+38h]
.text:1400A3154  FF 15 76 DF 04 00           call    [rip+4DF76h]                 ; RegCloseKey
.text:1400A315A                              loc_1400A315A:
.text:1400A315A  48 8D 0D CF BB 06 00        lea     rcx, [rip+6BBCFh]            ; "Kernel32.dll"
.text:1400A3161  FF 15 F9 E5 04 00           call    [rip+4E5F9h]                 ; LoadLibraryW
.text:1400A3167  48 8B C8                    mov     rcx, rax
.text:1400A316A  48 8D 15 A7 BB 06 00        lea     rdx, [rip+6BBA7h]            ; "SetDllDirectoryW"
.text:1400A3171  FF 15 F1 E6 04 00           call    [rip+4E6F1h]                 ; GetProcAddress
.text:1400A3177  48 85 C0                    test    rax, rax
.text:1400A317A  74 0D                       jz      short loc_1400A3189          ; target = 1400A3189
.text:1400A317C  48 8D 0D C1 71 05 00        lea     rcx, [rip+571C1h]            ; Buffer
.text:1400A3183  FF 15 1F F0 04 00           call    [rip+4F01Fh]                 ; _guard_dispatch_icall
```

This snippet is particularly instructive because it's dense with RIP-relative addressing: string literals (`Software\Microsoft\Windows NT\CurrentVersion`, `UBS`, `Kernel32.dll`, `SetDllDirectoryW`), IAT entries (`RegOpenKeyExW`, `RegQueryValueExW`, `RegCloseKey`, `LoadLibraryW`, `GetProcAddress`), global variables (`__security_cookie`, `Buffer`), and Control Flow Guard dispatch (`__guard_dispatch_icall_fptr`). It also contains relative control-flow instructions: a direct call to `sub_1400E8F50` and conditional branches (`jnz short loc_1400A315A`, `jz short loc_1400A3189`).

Suppose we want to insert `16` bytes at address `0x1400A310B`, the same location where we previously inserted bytes using the two classic methods. All instructions following this point will shift forward by 16 bytes. For instance, `call    [rip+4DFA0h]` moves from `0x1400A3112` to `0x1400A3122`. But this shift itself is not a concern—once the insertion happens, subsequent instructions naturally slide forward in memory. What does require attention are the relative offsets encoded within those instructions.

For control-flow instructions (JMP, CALL, JZ, JNZ, etc.), the target is encoded as a relative offset from the instruction pointer. There are four scenarios to consider:

1. Both instruction and target are before the insertion point: the relative distance remains unchanged—no fix needed.
2. Both instruction and target are after the insertion point: both shift by the same amount, so the relative distance remains unchanged—no fix needed.
3. Instruction is before the insertion point, but target is after: the target shifts while the instruction stays put—offset must be increased by the insertion size.
4. Instruction is after the insertion point, but target is before: the instruction shifts while the target stays put—offset must be decreased by the insertion size.

In the snippet shown, the `call sub_1400E8F50` at `0x1400A30E0` falls under scenario 3: the instruction lies before the insertion point, while its target (`0x1400E8F50`) lies after it, so the relative offset must be increased by 16. The same applies to the `call __chkstk` at `0x1400A309D`. The conditional branch `jnz short loc_1400A315A` at `0x1400A311A` falls under scenario 2, as does the `jz short loc_1400A3189` at `0x1400A317A`; both the instruction and the target are after the insertion point, so no adjustment is required.

RIP-relative addressing follows the same logic but presents a more complex picture. In this example, every `lea` and `call [rip+displacement]` instruction after the insertion point references data in sections outside .text that never move. Each of these instructions shifts by 16 bytes, but their targets don't, so every RIP-relative offset must be decreased by 16.

```asm
; ==================== AFTER 16-BYTE INSERTION AT 0x1400A310B ====================
; Inserted 16 bytes

.text:1400A3080  48 89 5C 24 10              mov     [rsp+10h], rbx
.text:1400A3085  55                          push    rbp
.text:1400A3086  56                          push    rsi
.text:1400A3087  57                          push    rdi
.text:1400A3088  41 54                       push    r12
.text:1400A308A  41 55                       push    r13
.text:1400A308C  41 56                       push    r14
.text:1400A308E  41 57                       push    r15
.text:1400A3090  48 8D AC 24 B0 B6 FF FF     lea     rbp, [rsp-4950h]
.text:1400A3098  B8 50 4A 00 00              mov     eax, 4A50h
.text:1400A309D  E8 DE 6A 01 00              call    __chkstk                     ; rel+=16
.text:1400A30A2  48 2B E0                    sub     rsp, rax
.text:1400A30A5  48 8B 05 D4 BF 09 00        mov     rax, [rip+9BFD4h]            ; No fix (before insertion -> .data)
.text:1400A30AC  48 33 C4                    xor     rax, rsp
.text:1400A30AF  48 89 85 40 49 00 00        mov     [rbp+4940h], rax
.text:1400A30B6  44 89 4C 24 78              mov     [rsp+78h], r9d
.text:1400A30BB  4C 89 45 20                 mov     [rbp+20h], r8
.text:1400A30BF  48 8B F1                    mov     rsi, rcx
.text:1400A30C2  48 89 4D 98                 mov     [rbp-68h], rcx
.text:1400A30C6  33 DB                       xor     ebx, ebx
.text:1400A30C8  89 5D 64                    mov     [rbp+64h], ebx
.text:1400A30CB  89 9D 54 01 00 00           mov     [rbp+154h], ebx
.text:1400A30D1  33 D2                       xor     edx, edx
.text:1400A30D3  41 B8 14 01 00 00           mov     r8d, 114h
.text:1400A30D9  48 8D 8D 58 01 00 00        lea     rcx, [rbp+158h]
.text:1400A30E0  E8 7B 5E 04 00              call    sub_1400E8F50                ; rel+=16
.text:1400A30E5  C7 85 50 01 00 00 1C 01 00 00  mov  [rbp+150h], 11Ch
.text:1400A30EF  48 8D 45 38                 lea     rax, [rbp+38h]
.text:1400A30F3  48 89 44 24 20              mov     [rsp+20h], rax
.text:1400A30F8  41 BD 01 00 00 00           mov     r13d, 1
.text:1400A30FE  45 8B CD                    mov     r9d, r13d
.text:1400A3101  45 33 C0                    xor     r8d, r8d
.text:1400A3104  48 8D 15 A5 BB 06 00        lea     rdx, [rip+6BBA5h]            ; No fix (before insertion -> .rdata)
;------------------------------------------------------------------------------------------------------------------------------------
.text:1400A310B  XX XX XX XX XX XX XX XX     ; <== INSERTED: 16 bytes payload
.text:1400A3113  XX XX XX XX XX XX XX XX     ;     (e.g., int3, logging stub, etc.)
.text:1400A311B  48 C7 C1 02 00 00 80        mov     rcx, 0FFFFFFFF80000002h      
.text:1400A3122  FF 15 90 DF 04 00           call    [rip+4DF90h]                 ; disp -= 16 (was 4DFA0h)
.text:1400A3128  85 C0                       test    eax, eax                     
.text:1400A312A  75 3E                       jnz     short loc_1400A316A          ; No fix (both after insertion)
.text:1400A312C  C7 45 78 04 00 00 00        mov     dword ptr [rbp+78h], 4
.text:1400A3133  48 8D 45 78                 lea     rax, [rbp+78h]
.text:1400A3137  48 89 44 24 28              mov     [rsp+28h], rax
.text:1400A313C  48 8D 85 60 01 00 00        lea     rax, [rbp+160h]
.text:1400A3143  48 89 44 24 20              mov     [rsp+20h], rax
.text:1400A3148  4C 8D 4D 74                 lea     r9, [rbp+74h]
.text:1400A314C  45 33 C0                    xor     r8d, r8d
.text:1400A314F  48 8D 15 BA BB 06 00        lea     rdx, [rip+6BBBAh]            ; disp -= 16 (was 6BBCAh)
.text:1400A3156  48 8B 4D 38                 mov     rcx, [rbp+38h]
.text:1400A315A  FF 15 50 DF 04 00           call    [rip+4DF50h]                 ; disp -= 16 (was 4DF60h)
.text:1400A3160  48 8B 4D 38                 mov     rcx, [rbp+38h]
.text:1400A3164  FF 15 66 DF 04 00           call    [rip+4DF66h]                 ; disp -= 16 (was 4DF76h)
.text:1400A316A                              loc_1400A316A:                       ; Target also shifted +16
.text:1400A316A  48 8D 0D BF BB 06 00        lea     rcx, [rip+6BBBFh]            ; disp -= 16 (was 6BBCFh)
.text:1400A3171  FF 15 E9 E5 04 00           call    [rip+4E5E9h]                 ; disp -= 16 (was 4E5F9h)
.text:1400A3177  48 8B C8                    mov     rcx, rax
.text:1400A317A  48 8D 15 97 BB 06 00        lea     rdx, [rip+6BB97h]            ; disp -= 16 (was 6BBA7h)
.text:1400A3181  FF 15 E1 E6 04 00           call    [rip+4E6E1h]                 ; disp -= 16 (was 4E6F1h)
.text:1400A3187  48 85 C0                    test    rax, rax
.text:1400A318A  74 0D                       jz      short loc_1400A3199          ; No fix (both after insertion)
.text:1400A318C  48 8D 0D B1 71 05 00        lea     rcx, [rip+571B1h]            ; disp -= 16 (was 571C1h)
.text:1400A3193  FF 15 0F F0 04 00           call    [rip+4F00Fh]                 ; disp -= 16 (was 4F01Fh)
```

The Procmon64 example is particularly illuminating because it demonstrates the density of relative references in typical Windows applications. In just this short snippet, we count:
- 2 direct calls via `E8 rel32` (__chkstk, sub_1400E8F50)
- 5 RIP-relative indirect calls through IAT via `FF 15 disp32` (RegOpenKeyExW, RegQueryValueExW, RegCloseKey, LoadLibraryW, GetProcAddress)
- 1 RIP-relative indirect call to CFG dispatch pointer (_guard_dispatch_icall)
- 5 RIP-relative data references via `lea reg, [rip+disp]` ("Software\Microsoft\Windows NT\CurrentVersion", "UBS", "Kernel32.dll", "SetDllDirectoryW", Buffer)
- 1 RIP-relative global variable access (`__security_cookie`)
- 2 conditional branches via short jump (`jnz short`, `jz short`)

In this snippet, most post-insertion RIP-relative references target non-text sections, so they require adjustment. Miss even one, and the program crashes or—worse—silently corrupts data.

Let's present the offset‑adjustment rules using two separate tables—one for control‑flow instructions and another for RIP‑relative addressing:

**Control-Flow Instructions (call rel32, jmp rel32, jcc rel8/rel32)**

| # | Instruction Location | Target Location | Instruction Shift | Target Shift | Action |
| --- | --- | --- | --- | --- | --- |
| 1 | Before insertion | Before insertion | 0 | 0 | No fix needed |
| 2 | After insertion | After insertion | +n | +n | No fix needed |
| 3 | Before insertion | After insertion | 0 | +n | Offset += n |
| 4 | After insertion | Before insertion | +n | 0 | Offset -= n |

**RIP-Relative Addressing (lea, mov [rip+...], call [rip+...], etc.)**

| # | Instruction Location | Target Region | Target Location | Instruction Shift | Target Shift | Action |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Before insertion | .text | Before insertion | 0 | 0 | No fix needed |
| 2 | Before insertion | .text | After insertion | 0 | +n | Offset += n |
| 3 | After insertion | .text | Before insertion | +n | 0 | Offset -= n |
| 4 | After insertion | .text | After insertion | +n | +n | No fix needed |
| 5 | Before insertion | Other sections | N/A | 0 | 0 | No fix needed |
| 6 | After insertion | Other sections | N/A | +n | 0 | Offset -= n |

Other sections include—but are not limited to—.data, .rdata, and .idata. In the Procmon64 example, all the string literals reside in .rdata, the IAT entries in .idata, and global variables like `__security_cookie` and `Buffer` in .data. None of these move when we insert bytes into .text, so any post-insertion RIP-relative reference that targets these non-moving sections falls under scenario 6 and must have its displacement decreased.


## The relocation table illusion: "Just fix .reloc, right?"

Every PE file specifies a preferred base address, but because of ASLR and potential address‑space conflicts with other loaded modules, the image often ends up being mapped elsewhere at runtime. When this occurs, all hardcoded absolute addresses inside the image must be adjusted accordingly—a process known as relocation.


<img width="1356" height="1090" alt="image" src="https://github.com/user-attachments/assets/874c47a0-94f5-4aec-8e03-1d61907f00ae" />


At load time, the OS calculates the delta between the preferred base and the actual base, then applies this delta to every hardcoded address listed in the relocation table. For example, if the preferred base is `0x140000000` but the image loads at `0x7ff693dc0000`, the delta is `0x7ff693dc0000 - 0x140000000 = 0x7ff552dc0000`. A hardcoded address like `0x1400b94b0` would be updated to `0x1400b94b0 + 0x7ff552dc0000 = 0x7ff693e794b0`.

Now consider what happens when performing in‑place insertion. Inserting bytes at a given address shifts all subsequent code forward. Any relocation entry that refers to an address beyond the insertion point will now point to the wrong location—the hardcoded value it describes has moved.

Earlier, we used the two classic techniques—adding a new section and hunting for a code cave—to inject code at `0x1400a310b` in Procmon64.exe. In both cases, the original instructions remain untouched, so nothing in the existing layout shifts. Now consider achieving the same result through in‑place insertion. Because every instruction after the insertion point is pushed forward, any relocation entry whose RVA exceeds `0x0a310b` must be adjusted. For example, `0x1400b94b0 (RVA 0x0b94b0)` lies beyond the insertion point and therefore needs to be updated, while `0x140002ed0 (RVA 0x02ed0)` lies before it and remains unchanged.

This is yet another consequence of shifting code: relocation entries, just like relative offsets, must remain synchronized with the bytes they describe.



## These are the challenges everyone expects. The real problems? Elsewhere

In summary, control‑flow instructions, RIP‑relative addressing, and hardcoded addresses are the most obvious factors that come to mind. But the real challenges run far deeper—far more complex and subtle than they initially appear.


# Drawing the Line: Scope, Non-Goals, and Caveats

With the initial introduction to in-place insertion complete, the next step is to clearly define our scope. Without firm boundaries, it’s all too easy to disappear into an ocean of edge cases.

Our focus is x64 native PE files compiled by MSVC (C/C++), with no packing or obfuscation applied.

Packed or obfuscated binaries are deliberately excluded. The reasoning is simple: packing and obfuscation introduce layers of complexity for both reverse engineers and tooling. The goal of in‑place insertion is to address a specific pain point in the reverse‑engineering workflow—not to simultaneously solve unpacking or deobfuscation. Those challenges are best handled by tools purpose‑built for them.

We also narrow our attention to MSVC‑compiled programs. Although the ecosystem of native languages has expanded, C and C++ still dominate the Windows executable landscape, and they remain the primary targets of disassemblers. Binaries produced by Go, Rust, and other non‑managed languages come with their own structural quirks and reverse‑engineering hurdles. Their comparatively small presence makes them a poor fit for this stage of development and a likely source of scope creep.

Managed‑language executables, such as those built with C#, are likewise outside our focus. Tools like dnSpy already provide source‑level reconstruction, leaving little room for in‑place byte insertion to offer meaningful benefit.

In short, while “non‑obfuscated, non‑packed, MSVC‑compiled x64 PE” may sound restrictive, this category covers the overwhelming majority of Windows utilities, commercial software, and game binaries—the very targets most frequently analyzed in practice. This isn’t a limitation; it’s a deliberate, pragmatic focus on where the technique delivers real value.




# The Core Trick: Segmented Absorption Algorithm

## The naive approach: Whole-shift and its reference nightmare
In the previous sections, we used the `WinMain` function of Procmon64.exe to introduce in-place insertion. The code snippet shown was deliberately limited; within that excerpt, several instructions required adjustment, but beyond what was shown, far more would need fixing throughout the .text section. We discussed 4 scenarios for control-flow instructions, 6 scenarios for RIP-relative addressing, and the necessary adjustments for relocation-backed absolute addresses.

Yet all of this assumes the simplest form of in-place insertion: shift all subsequent instructions forward, relying on sufficient free bytes at the end of the .text section to avoid breaking section boundaries. This naive model introduces two notable problems:

Reference volume becomes a nightmare. Depending on binary size, complexity, and insertion address, the number of affected references can explode. Even though we don't fix them manually—the algorithm handles that—a larger reference count means higher probability of missed edge cases or reference types we haven't anticipated. And in-place insertion demands 100% accuracy. Not 98%, not 99%. A single missed reference means a crash or corrupted execution.
Insertion capacity is constrained by trailing free space. The maximum insertion size depends entirely on how many unused bytes exist at the end of the .text section. While there's almost always some slack, it may not be nearly enough. Recall that Process Monitor's .text section has only 132 bytes of trailing space—sufficient for a reverse engineer inserting a few instructions, but wholly inadequate for shellcode injection in red team or penetration testing scenarios.

These two constraints—reference explosion and limited insertion capacity—directly motivated the core innovation of this work: the Segmented Absorption Algorithm.


## The insight: Compilers leave breadcrumbs 

The good news is that compilers generously leave us a gift: free bytes scattered within and between functions. The following two screenshots illustrate this—free bytes identified at the CRT entry point and at the end of a function, respectively.

<img width="1158" height="718" alt="image" src="https://github.com/user-attachments/assets/3f89900c-9005-499e-9edd-752e39247535" />


<img width="1337" height="721" alt="image" src="https://github.com/user-attachments/assets/87f8701a-108d-41e6-a79e-d9ff837ed542" />

These free bytes are typically 0xCC (INT3) or 0x00, inserted by the compiler to achieve alignment padding (4-byte, 16-byte, etc.) for performance optimization, calling convention requirements, or SIMD instruction alignment. These compiler-inserted gaps are our gift: we no longer need to rely solely on trailing free space at the end of the .text section. Instead, we can harvest these breadcrumbs scattered throughout the code.

If these breadcrumbs collectively provide sufficient free bytes—and they often do—we can avoid touching the trailing space entirely, sidestepping the reference nightmare of the naive whole-shift approach.

This is the key insight behind the Segmented Absorption Algorithm: rather than shifting everything to consume trailing space at the .text section's end, we absorb the insertion incrementally using the breadcrumbs—free bytes within and between functions—distributing the shift across multiple small padding regions instead of one massive displacement.


## Zone-by-zone absorption: Shift 16 → 13 → 3 → 2 → 0

Now that the core idea is clear—use internal breadcrumbs instead of relying on trailing space—let’s walk through a concrete example using Process Monitor. Our insertion point is `0xA310B`, an instruction inside the main function, and this time we’ll perform a true in‑place insertion.

Before the actual insertion, let's analyze available breadcrumbs. For demonstration, we set the insertion size to 16 bytes—neither too small to be trivial nor too large to introduce unnecessary complexity at this stage. This size is also practical and reasonable for logic-flipping during a typical reverse engineering workflow.

We use the script to enumerate available breadcrumbs from the insertion point to the trailing space:

```powershell
python .\BinaryScalpel.py  .\sysinternals\Procmon64.exe -m 3 -a A310B -s 16
Method 3: In-Place Byte Insertion
Insertion Point: 0x000A310B (File: 0x0A250B)
Insertion size: 16 bytes

======================================================================
PE BYTE INSERTION IMPACT ANALYSIS (Method 3)
======================================================================

.text Section Info:
  RVA:          0x00001000
  VirtualSize:  0xEF17C (979324 bytes)
  RawSize:      0xEF200 (979456 bytes)
  RawOffset:    0x400
  RawEnd:       0xEF600

Insertion Point:     0x000A310B (File: 0x0A250B)
Insertion Size:      16 bytes
Affected Range:      0x000A310B (File: 0x0A250B)
                  to 0x000A6929 (File: 0x0A5D29)

Padding Analysis:
  Total Available:   7032 bytes (0x1B78)

  Free Byte Sequences (before .text tail):
    Sequence 1: 3 bytes at 0xA5F0D (0xA530D)
    Sequence 2: 10 bytes at 0xA6436 (0xA5836)
    Sequence 3: 1 bytes at 0xA68CD (0xA5CCD)
    Sequence 4: 9 bytes at 0xA6927 (0xA5D27)
    Sequence 5: 15 bytes at 0xA6B61 (0xA5F61)
    Sequence 6: 6 bytes at 0xA6BCA (0xA5FCA)
    Sequence 7: 9 bytes at 0xA84E7 (0xA78E7)
    Sequence 8: 3 bytes at 0xA8A3D (0xA7E3D)
    Sequence 9: 12 bytes at 0xA8B34 (0xA7F34)
    Sequence 10: 13 bytes at 0xA8BB3 (0xA7FB3)
    ... and 1310 more sequences

  Total internal padding (before .text tail): 6900 bytes (0x1AF4)
  Trailing padding (.text tail):          132 bytes (0x84)
...<SNIP>...
```

Per the output, address `0x1400A5F0D` marks the end of the main function—3 free bytes. Address `0x1400A6436` marks the end of the following function—10 free bytes. Generous!

<img width="976" height="414" alt="image" src="https://github.com/user-attachments/assets/9d10574f-2101-4b1a-b9ba-9669f54c33fe" />

<img width="969" height="419" alt="image" src="https://github.com/user-attachments/assets/4fe8ec7c-ad70-45e0-9d8a-a893204b113d" />

In this way, we validated all identified breadcrumbs needed to absorb the insertion. While we cannot guarantee 100% of free bytes are discovered, we ensure every identified breadcrumb is safe to use—no false positives. Unless the insertion size is absurdly large, a few missed breadcrumbs are irrelevant. The script identified **6,900 bytes** of internal padding. For a 16-byte insertion? Absolute overkill.

To absorb our 16 inserted bytes, we need only 4 breadcrumbs:

```
Insert 16 bytes
       │
       ▼
   ┌───────────────────────────────────────────────────────────┐
   │ 16 ──(absorb 3)──► 13 ──(absorb 10)──► 3 ──(absorb 1)──► 2 ──(absorb 2)──► 0 │
   │  ↑                  ↑                   ↑                  ↑                 │
   │ 0xA310B          0xA5F10            0xA6446            0xA68CE               │
   └───────────────────────────────────────────────────────────┘
```


Note that the fourth breadcrumb has 9 bytes available, but we only consume 2—the remaining 7 bytes stay untouched. Segmented Absorption takes only what it needs. The script calculates exactly how each zone absorbs its share of the inserted bytes:


```powershell
...<SNIP>...
✨ SEGMENTED ABSORPTION (4 zones)
   Function-internal padding can absorb all inserted bytes.
   This minimizes references to fix - .text trailing space untouched.

  Shift Zones:
    Zone 1: 0xA310B (0xA250B) - 0xA5F0D (0xA530D)
            Shift: 16 bytes → absorbed by 3 bytes at 0xA5F0D (0xA530D)
    Zone 2: 0xA5F10 (0xA5310) - 0xA6436 (0xA5836)
            Shift: 13 bytes → absorbed by 10 bytes at 0xA6436 (0xA5836)
    Zone 3: 0xA6440 (0xA5840) - 0xA68CD (0xA5CCD)
            Shift: 3 bytes → absorbed by 1 bytes at 0xA68CD (0xA5CCD)
    Zone 4: 0xA68CE (0xA5CCE) - 0xA6927 (0xA5D27)
            Shift: 2 bytes → absorbed by 2 bytes at 0xA6927 (0xA5D27)
...<SNIP>...
```


Our approach intentionally favors caution: false negatives (missed padding) merely reduce the number of absorption points, which is harmless. A false positive, however, would overwrite live code or data and cause immediate corruption. With 6,900 bytes of confirmed padding, we can afford to be conservative. The safety margin is so large that missed breadcrumbs simply don’t matter.


## The math: delta = target_shift - location_shift

When we adopted the naive approach—shifting all subsequent instructions forward—we discussed 4 scenarios for adjusting control-flow instruction offsets. With the Segmented Absorption Algorithm, different zones shift by different amounts: instructions in Zone 1 shift by 16 bytes, those in Zone 2 by 13 bytes, and so on. This might seem to complicate matters, but in fact, we need only one formula:

```
delta = target_shift - location_shift
new_offset = old_offset + delta
```

### Example 1: Target before insertion point

Consider the call instruction at `0x1400A31F2`, which calls a function located at `0x140005E70`—before the insertion point and therefore unaffected by any shift. The original opcode is `E8 79 2C F6 FF`.

<img width="989" height="495" alt="image" src="https://github.com/user-attachments/assets/bd447d48-6906-4e69-b4f7-0fc0a3a0baf1" />

After the 16-byte insertion, the opcode becomes `E8 69 2C F6 FF`—the offset decreased by `0x10` bytes. This is expected: the instruction shifted forward by `16` bytes while the target remained stationary.

<img width="996" height="381" alt="image" src="https://github.com/user-attachments/assets/66f9e013-e0d4-4722-b24d-20cd0decabcc" />

### Example 2: Cross-zone call (Zone 3 → Zone 2)

A more interesting case: the call instruction at `0x1400A67AE`, located in `Zone 3`, calls `0x1400A5F10`—the start of `Zone 2`, immediately following the main function. The original opcode is `E8 5D F7 FF FF`.

<img width="985" height="330" alt="image" src="https://github.com/user-attachments/assets/3e582bf4-3724-4ee3-9520-246b6aa8f484" />

After insertion, the instruction resides at `0x1400A67B1` with opcode `E8 67 F7 FF FF`. Let's verify:

- Instruction shifted: `0x1400A67B1 - 0x1400A67AE = 3 bytes (Zone 3)`
- Target shifted: `0x1400A5F1D - 0x1400A5F10 = 13 bytes (Zone 2)`
- Delta: `13 - 3 = 10`
- New offset: `0xfffffffffffff75d + 0xa = 0xfffffffffffff767` 

One formula, all cases covered.

<img width="1019" height="367" alt="image" src="https://github.com/user-attachments/assets/bd7b4eb7-19fb-4ce5-8e9f-5892a6488aaa" />

You might have noticed something puzzling: the instruction is in Zone 3, and we said Zone 3's breadcrumb is 1 byte—so why did the address shift by 3 bytes, not 1? The answer lies in how shift amounts accumulate across zones. Let's clarify this in the next sub-section.

## Why process back-to-front (or corrupt everything)

The answer is intuitive: if we shift from Zone 1 toward the last zone, we corrupt data as we go. Once Zone 1's content shifts forward, it overwrites part of Zone 2—before Zone 2 has had a chance to move. The result is irreversible corruption.
To avoid this, we shift in reverse order—from the last zone back to Zone 1:

- Zone 4: Shift 2 bytes
- Zone 3: Shift 2 + 1 = 3 bytes
- Zone 2: Shift 2 + 1 + 10 = 13 bytes
- Zone 1: Shift 2 + 1 + 10 + 3 = 16 bytes

The pattern is intuitive: each zone's shift is the cumulative sum of all absorptions from that point onward.
Think of it like moving boxes out of a narrow hallway—you start with the box closest to the door. Move the innermost box first, and you'll shove it straight into the others.

## Shrinking the Blast Radius

Beyond avoiding reliance on trailing space, the Segmented Absorption Algorithm offers another major advantage: the affected range is confined to only the zones needed for absorption, rather than spanning the entire .text section.

In the naive whole-shift approach, inserting 16 bytes near the start of a 1MB .text section means every reference across that entire megabyte must be examined and potentially fixed. With Segmented Absorption, the affected range in our example extends only from `0xA310B` to `0xA6930`, roughly 14KB instead of 900KB+. The number of references requiring adjustment drops dramatically.

The script calculates exactly which zones are needed and reports the affected range:

```powershell
Affected Range:      0x000A310B (File: 0x0A250B)
                  to 0x000A6929 (File: 0x0A5D29)
```

Fewer affected bytes means fewer references to fix, which means lower probability of encountering an unhandled edge case. This is how Segmented Absorption tames the reference nightmare.

In summary, the Segmented Absorption Algorithm is conceptually intuitive: harvest breadcrumbs, compute cumulative shifts, process back‑to‑front. But once we began implementing it, nearly every assumption—what counts as ‘padding,’ what counts as a ‘reference’—proved far more treacherous than expected.


# The Map: Reference Type Taxonomy

Control‑flow instructions, RIP‑relative addressing, and hardcoded addresses are the reference types that naturally come to mind when thinking about in‑place insertion. But depending on source‑code patterns, compiler settings, and enabled security features, the landscape is far broader—well beyond this initial trio.

The table below catalogs the reference types we encountered during research and tool development. While it may not be exhaustive, it has proven remarkably robust: the tool successfully processed 78 real‑world executables across a wide range of sizes and categories—Sysinternals utilities, built‑in Windows tools, online game server and client program, and security software—with consistently strong results.

## 15+ reference types you must handle
| | | | |
| --- | --- | --- |   --- |
| Reference Type | Detection Source| 	Fix Method| Guardrail to Avoid Misidentification |
| Control Flow (E8/E9/0F 8x) | 	Code disassembly | 	Adjust rel32: new = old + (target_shift - loc_shift)  | Opcode prefix uniquely identifies instruction type |
| Short Jump (EB, 7x) | 	Code disassembly | 	Adjust rel8 (check overflow) | Opcode prefix uniquely identifies instruction type |
| RIP-Relative Memory | 	Code disassembly | 	Adjust disp32: new = old + (target_shift - loc_shift) | ModR/M byte with RIP base register | 
| DISP32_TEXT_PTR | 	Non-RIP memory operand with .text displacement | 	Add target_shift to displacement | Non-RIP base register + displacement within .text range + scale factor of 4 |
| Absolute Address | 	.reloc table | 	Add shift to VA | Parse .reloc section accurately |
| Delay IAT Entry | Delay Import Directory | Add shift to VA | Parse Delay Load Import directory accurately |
| TLS Callback | 	TLS Directory | 	Add shift to VA | Parse TLS directory accurately|
| CFG Entry | 	Load Config | 	Add shift to VA or Disable CFG | Parse Load Config directory accurately |
| Exception Handler Begin/End | 	.pdata table | 	Add shift to RVA | Parse Exception directory accurately |
| UNWIND_INFO Handler | 	UNWIND_INFO structures | 	Add shift to handler RVA | Parse Exception directory accurately; exclude from jump table heuristic scan  |
| Export Function | 	Export Directory | 	Add shift to RVA | Parse Export directory accurately |
| Entry Point | 	PE Optional Header | 	Add shift to RVA | Parse Optional header accurately|
| Jump Table Entry in data sections | 	Heuristic scan in data sections| 	Add shift to RVA | RVAs pointing to .text; exclude UNWIND_INFO and CFG regions |
| Jump Table Entries in .text section | 	DISP32_TEXT_PTR pattern match | 	Add shift to RVA (with location_shift) | Located at displacement address |
| Function Pointer (32-bit RVA) | 	Match .pdata function starts | 	Add shift to RVA | Value matches known function entry from .pdata |


Thanks to the Segmented Absorption Algorithm, we don't need to scan and fix references across the entire .text section. Only references whose location or target falls within the affected range require examination. A call instruction at `0x1000` targeting `0x2000` needs no adjustment if both addresses lie outside the affected zones—the relative distance between them remains unchanged. This dramatically reduces the working set: instead of processing every reference in a multi-megabyte binary, we focus only on those that cross zone boundaries or reside within shifted regions.

That said, even within the affected range, a single VA or RVA may fall into multiple categories. If not tracked properly, this leads to duplicate updates—a major pitfall we will discuss shortly.


# The Abyss: Complexity That Wasn't in the Manual

The previous table tells you what to fix. This chapter is about why it's harder than it looks.

The complexity emerges from multiple directions: tooling constraints that hide critical details, ordering dependencies that corrupt data if mishandled, edge cases that masquerade as safe patterns, and PE structures that only surface in specific compiler configurations. Each subsection that follows represents a lesson learned the hard way—usually through crashes.

## The Uncommon but Critical: PE Structures That Bite

Control-flow instructions and RIP-relative addressing are familiar territory for anyone who has worked with x86-64 disassembly. But PE files contain other structures—less frequently encountered, rarely discussed in tutorials—that also embed code addresses. Miss any of them, and the patched binary will crash under specific conditions.

### TLS Callbacks: Execute before main(), must be updated

Thread Local Storage (TLS) callbacks are functions that run automatically whenever a thread is created or destroyed—including the main thread at program startup. In practice, this means TLS callbacks execute before the Entry Point, before main(), and before any user‑level code.

Inspecting Process Monitor’s TLS Directory in PE Bear reveals several virtual addresses. None of the directory fields themselves (StartAddressOfRawData, EndAddressOfRawData, and so on) fall within .text; they reside in .data or .rdata.

<img width="1102" height="393" alt="image" src="https://github.com/user-attachments/assets/462067d2-75bf-41b0-83c1-efaffb84b765" />

The critical field is AddressOfCallBacks, which points to an array of callback function addresses—and these callbacks do live in .text. For our 16‑byte insertion at `0xA310B`, with the shifted region extending to `0xA6929`, we must verify whether any TLS callback lies inside that range. In this case, none do, so no adjustment is needed.

<img width="661" height="309" alt="image" src="https://github.com/user-attachments/assets/7e6f18e5-e909-419a-9050-04a3a7052597" />

But when they do fall inside the shifted region, the consequences are immediate and severe: if a TLS callback address isn’t updated, the loader will jump into garbage on the very first instruction—before the program has even begun to run.



### CFG Tables: The GuardFlags entry_size trap

Control Flow Guard (CFG) is a security mitigation that verifies the legitimacy of indirect call targets at runtime. When enabled, several fields in the Load Config Directory—such as GuardCFFunctionTable, GuardCFCheckFunctionPointer, GuardCFDispatchFunctionPointer, and others—reference arrays of valid function targets.

<img width="1028" height="662" alt="image" src="https://github.com/user-attachments/assets/f8156c24-ef39-4ee4-a21c-20631018bee4" />

Although some of directory fields are themselves virtual addresses, none of them fall within .text, much less within our affected range. The arrays they reference, however, contain function RVAs that do point into .text. Any entry that lands inside the shifted region would need to be updated.

This is where things become less straightforward. While the Load Config Directory is a well-defined PE structure, its contents have evolved significantly across Windows and MSVC versions: new security-related fields have been added over time, entry layouts vary depending on enabled GuardFlags, and several tables require careful deduplication. Supporting every historical and modern variant robustly would require substantial version-aware parsing logic beyond the current scope.

A more pragmatic solution is simply to disable CFG by clearing the relevant flags.

For reverse engineers, this has no downside—CFG is a runtime defense and irrelevant to static analysis. For offensive security practitioners, modifying a signed binary already invalidates its checksum, signature, and other integrity checks. Disabling one additional mitigation adds no meaningful impact.




### Delay-Import IAT: Absolute Addresses in Disguise

Delay‑loaded imports are resolved on first use rather than at load time. The Delay Import Descriptor contains several address fields, but the key one is the delay‑import IAT (Import Address Table). Unlike regular imports—which store RVAs—delay‑import IAT entries are 64‑bit absolute virtual addresses pointing to thunks in the .text section. Before the first call to a delay‑loaded function, each thunk contains a small stub that triggers the resolver; after resolution, the stub is overwritten with the function’s actual address.

<img width="1135" height="1004" alt="image" src="https://github.com/user-attachments/assets/63912d46-1613-452c-b1ba-c66c1915a32b" />

A concrete example comes from the well‑known security tool mimikatz.exe, which includes two delay‑loaded modules. Inspecting the IAT field of the first descriptor shows a sequence of virtual addresses in the hex view, each one targeting a thunk in .text. As with any other reference type, if any of these addresses fall within the affected range, they must be updated accordingly.




### UNWIND_INFO Handlers: The Hidden Exception Handler RVA

Every x64 PE includes a .pdata section containing `RUNTIME_FUNCTION` entries that map code ranges to their corresponding unwind information. Each entry’s `UnwindInfoAddress` points to an `UNWIND_INFO` structure, which—depending on the Flags value—may include an RVA referencing an exception handler located in .text.

```c
typedef struct _UNWIND_INFO {
    UBYTE Version : 3;
    UBYTE Flags   : 5;    // UNW_FLAG_EHANDLER (0x01) or UNW_FLAG_UHANDLER (0x02)
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode[...];
    // Only present if Flags contains EHANDLER or UHANDLER:
    ULONG ExceptionHandler;   // ← RVA to handler function
    ULONG ExceptionData[];
} UNWIND_INFO;
```

These entries have no fixed size; their length depends on both `Flags` and `CountOfCodes`.

Returning to Process Monitor: examining the RUNTIME_FUNCTION entry at offset `0x1436E4` shows UnwindInfoAddress pointing to RVA `0x12D520`. The first byte (0x19) decodes to Version = 1 and Flags = 3, meaning both an exception handler and an unwind handler are present (and in this case, they share the same code). The handler RVA is `0xB94FC`.

<img width="997" height="632" alt="image" src="https://github.com/user-attachments/assets/6e3865c7-7384-440d-baad-e99d738f1b07" />


If such a handler falls within the affected range and isn’t updated, the program may appear to run normally—until an exception is thrown. Only then does the OS consult the stale RVA and jump into corrupted code. It becomes a delayed‑trigger failure rather than an immediate crash, and far trickier to diagnose.

The reference types in this subsection are not algorithmically complex—once you know they exist, handling them is straightforward. The real danger is ignorance: these structures rarely appear in tutorials or typical reverse engineering workflows. Their existence only becomes apparent when a patched binary crashes under specific conditions. We document them here as a checklist for implementers.

| Structure | Consequence of Missing It | Complexity to Fix |
| --- | --- | --- |
| TLS Callbacks | Crash before main() | Low |
| CFG Tables | Crash on indirect call (if CFG enabled) | High for fix, low for disabling CFG |
| Delay-Import Table | Crash on first call to delay-loaded function | Low |
| UNWIND_INFO Handler | Crash when exception is thrown | Medium |


## DISP32_TEXT_PTR: The Reference Type Nobody Documented

RIP-relative addressing is one of the most obvious reference types that comes to mind. However, there exists a less obvious category—instructions that superficially resemble both RIP-relative and normal DISP32 forms. We call this category `DISP32_TEXT_PTR`.

The format for RIP-relative addressing is `mov rax, [rip+0x1234]`. Normal DISP32 instructions look like `mov rax, [rbx+0x10]`, where the displacement is a small value (far less than `0x1000`). DISP32_TEXT_PTR looks like `mov ecx, [rsi + rax*4 + 0xC388]` or `mov rax, [rax+0x1234]`. RIP-relative instructions are trivial to identify, and normal DISP32 instructions are typically used to access structure fields. But for DISP32_TEXT_PTR, the displacement is a 32-bit value that most of the time represents an RVA. If this RVA falls within the .text section—especially within our affected range—it must be updated.

During extensive testing, we first encountered DISP32_TEXT_PTR failures when testing DiskView64.exe and Autologon64.exe, both part of the Sysinternals suite. Why is DISP32_TEXT_PTR difficult to recognize at first? When seeing an instruction like `mov ecx, [rsi + rax*4 + 0xC388]`, one might initially assume `0xC388` is a structure or array offset. But structures larger than 0x1000 bytes are rare, let alone ones requiring a displacement as large as 0xC388. Even when accessing very large structures, compilers typically use a different approach—computing the address with LEA first, or chaining multiple pointer dereferences.


The test configuration was to insert 480 bytes of NOP at the entry point of DiskView64.exe (0xB084) and Autologon64.exe (0x3DC4). When testing the patched DiskView64.exe, the program immediately crashed. Through debugging, we identified the culprit at `0xBFB0`: `mov ecx,  [rsi + rax*4 + 0xC388]`—a jump table lookup where 0xC388 is an RVA, not a structure offset.

<img width="757" height="218" alt="image" src="https://github.com/user-attachments/assets/2ba514af-fb7e-4bcd-9d55-04ab85d26649" />

Let's examine the affected range for DiskView64.exe with 480 NOPs inserted at the entry point:

```powershell
Affected Range:      0x0000B084 (File: 0x00A484)
                  to 0x00012F31 (File: 0x012331)
```

0xC388 falls squarely within this range—it must be updated. This revealed a new reference type: non-RIP memory operands with displacements pointing into .text. We had already handled RIP-relative addressing, but this variant slipped through.

Similarly, we identified `mov ecx, [r8 + r9*4 + 0x4EE7]` at address `0x4EDA` in Autologon64.exe. 

//New added: As we can see, the inline jump table starts from 0x4EE7. Instruction `LEA R9, [RIP-0x4EDA]` trickly set R9 as 0, so that `r8 + r9*4 + 0x4EE7` is essentially `r9*4 + 0x4EE7`, 0x4ee7 is the displacement, r9 is the index for RVA. In this way, the code for the chosen Case was redirected. 

```asm
LEA R9, [RIP-0x4EDA]  ; R9=0
MOV ECX, [R8 + R9*4 + 0x4EE7]
ADD RCX, R9
JMP RCX
```



After the shift, the jump table entries themselves were updated correctly, but the displacement in the instruction was not—it still pointed to the old address, which now contained different code.

<img width="639" height="273" alt="image" src="https://github.com/user-attachments/assets/a58ec66d-67d5-4f5d-b43d-3f2f7e0694f9" />


<img width="734" height="95" alt="image" src="https://github.com/user-attachments/assets/5b5a13cc-8179-48f5-b427-f09a354f2ace" />

With this lesson learned, we added detection for DISP32_TEXT_PTR: for any memory operand with a non-RIP base register, we check whether the displacement falls within the affected range. While this could theoretically produce false positives (a large structure offset coincidentally matching a .text address), such cases are rare in practice—structure offsets are typically small, while .text RVAs are large. In our testing across 78 executables, this heuristic produced no observed false positives.

Finally, let's compare these three instruction types side by side:

|  | RIP-Relative | Normal DISP32 | DISP32_TEXT_PTR | 
| --- | --- | --- | --- | 
| Form | `mov rax, [rip+0x1234]` | `mov rax, [rbx+0x10]` | `mov ecx, [rsi + rax*4 + 0xC388]` |
| Meaning of displacement | Offset from current instruction | Structure or array offset | RVA in .text section |
| Typical usage | Access global variables, strings, etc. | Access object fields, stack variables, etc. | Jump table lookup | 
| Target location | Various sections | Typically stack/heap| .text section | 
| Does displacement change as instruction shifts? | Yes, the distance changes | No | No, but the target moves |
| Needs fix? | Yes | No | Yes |
| Fix formula | delta = target_shift - location_shift | N/A | new = old + target_shift | 
| Likelihood of being overlooked | Low | N/A | High |


## The Padding Minefield: When 0x00 and 0xCC Lie to You

We love breadcrums, they offer us free bytes! But sometime, seemingly free bytes can be a trap, they are not free byte that we love at all! Maybe you can guess that we should not rely on single or even double 0x00 or 0xcc byte sequence, they can be part of an instruction. But in practice, it is difficult to avoid all of them at first time, especially if you want to balance of utilizing free bytes sequence and avoiding any possible trap.

### Jump Table RVAs Masquerading as Null Padding/Jump Tables in .text: Data Hiding in Plain Sight

When testing Streams64.exe (another Sysinternals utility), we observed a puzzling behavior: the patched program ran correctly after inserting 79 bytes of NOP at the entry point, but crashed with 80 bytes. While larger insertions are more likely to encounter edge cases—eventually hitting the true safe upper boundary—79 bytes seemed suspiciously low. Something else was going on.

Examining the bytes starting at `0x4CB5` revealed the truth. Address `0x4CB5` contains the last valid instruction (jmp rcx). Beyond that, the disassembler shows a stream of nonsensical instructions: `ADD BYTE PTR [RBP], CL`, `ADD BYTE PTR [RDI], BL`, and so on. These are not real instructions—they are jump table entries, 32-bit RVAs whose high bytes are often 0x00, easily mistaken for null padding.

<img width="754" height="307" alt="image" src="https://github.com/user-attachments/assets/961c24ca-fd47-4281-9b23-0ebc43646eb1" />

Here is what the bytes actually represent:

| Address | Byte | Mapped Instruction |
| --- | --- | --- | 
| 0x4CB7 | 00 4D 00 00 | `RET` |
| 0x4CBB | 1F 4D 00 00 | `MOVZX EXC, WORD PTR [RDX]` |
| 0x4CBF | 01 4D 00 00 | `MOVZX EXC, BYTE PTR [RDX]` |
| 0x4CC3 | 0F 4D 00 00 | `MOVZX EXC, WORD PTR [RDX]` |

Notice the problem: these RVAs are small values (< 0x10000), so their upper bytes are `00 00`. To our padding detection, sequences like `4D 00 00` look like potential free bytes.

Comparing the affected ranges explains the 79 vs 80 byte mystery:

```
// Insert 79 bytes
Affected Range: 0x000040D8 to 0x00004C29

// Insert 80 bytes
Affected Range: 0x000040D8 to 0x00005056
                             ^^^^^^^^^^
                             Now includes 0x4CB7 (jump table start)
```

With 79 bytes, the jump table at `0x4CB7` lies outside the affected range—untouched. With 80 bytes, `0x4CB7` falls inside the range, and its 00 bytes get misidentified as padding, consumed as breadcrumbs, and overwritten. The jump table is corrupted; the switch statement jumps to garbage.

The fix requires a two-phase approach:
1. Identify jump tables first — Before padding detection, scan for jump table patterns and build a list of excluded regions.
2. Exclude during padding detection — When evaluating potential breadcrumbs, reject any region that overlaps with known jump tables.

This defense-in-depth ensures that data masquerading as padding cannot be mistakenly absorbed.


### The movabs Division Constant Trap

To be honest, this case left us speechless. The test configuration was to insert 640 bytes of NOP at the entry point of Bginfo64.exe, another Sysinternals utility. After investigation, we finally identified the corrupted instruction at `0x1A6DA5` in the original binary:

```
movabs rax, 0xCCCCCCCCCCCCCCCD
```

<img width="696" height="209" alt="image" src="https://github.com/user-attachments/assets/35c57012-439a-41b4-acf4-5eb7a91d35e7" />

You probably laughed the moment you saw it—and immediately understood the problem.

In earlier development, we had already considered scenarios where instruction operands contain `0x00` or `0xCC` bytes, and added rules to avoid misidentifying them as free bytes. But we never anticipated an operand with seven consecutive `0xCC` bytes. The constant `0xCCCCCCCCCCCCCCCD` is a magic number used by MSVC for fast division by 10—and it nearly fooled our padding detection.

The fix required refining our heuristics:

1. 2–7 consecutive 0xCC bytes: Check the preceding bytes for patterns like 48 B8 (the movabs opcode prefix). If present, these 0xCC bytes are likely part of an operand—reject as padding.
2. 8+ consecutive 0xCC bytes: Safe to treat as padding. No instruction operand can be this long.

A single magic constant taught us that even "obviously safe" patterns have edge cases hiding in compiler-generated code.



## Disassembly Wars: Linear vs. Recursive vs. Hybrid

The choice of disassembly strategy matters more than one might expect. Without the proper approach, critical references can be missed entirely.

Disassembling x64 code may sound straightforward: decode bytes, print mnemonics, repeat. In practice, however, the .text section is not a clean stream of instructions. Compilers embed data inline—jump tables, alignment padding, constants. A disassembler must decide what to do when it encounters non-code bytes. 

### The Spectrum of Disassembly Strategies

Linear disassembly decodes sequentially from a starting address. When encountering embedded data, two outcomes are possible:

- Garbage decoding: Data bytes happen to form valid opcodes → decoded as nonsense instructions, causing subsequent bytes to be misaligned
- Halt: Data bytes form an invalid instruction sequence → disassembly stops entirely

Both outcomes result in missing or corrupting all subsequent valid instructions, like the below code snippet illustrates:

```asm
0x4D68: mov rax, r11      ; Valid instruction
0x4D6B: ret               ; Valid instruction
0x4D6C: fimul [rbp]       ; Garbage (actually jump table entry 0x4DDE)
0x4D6F: add bl, bl        ; Garbage (actually jump table entry 0x4DDB)  
0x4D71: ???               ; HALTED (0x4D 00 00 is invalid)
0x4DBA: mov eax, [...]    ; NEVER REACHED (DISP32_TEXT_PTR here!)
```

Recursive disassembly solves this by maintaining a queue of addresses collected from control-flow instructions. Even when one path terminates, disassembly continues from saved branch targets:

```
0x4CA0: mov r11, rcx      ; Disassembled
0x4CB8: jbe 0x4DB0        ; Disassembled; target 0x4DB0 added to queue
        ...
0x4D6B: ret               ; Current path ends; pop 0x4DB0 from queue
0x4D6C: [JUMP TABLE]      ; Skipped (not in queue)
0x4DB0: mov rdx, r9       ; Disassembly resumes from queue
0x4DBA: mov eax, [r9+r8*4+0x4D6C]  ; DISP32_TEXT_PTR found!
```

With this background, let's dive deep into a case study to learn that choice of strategy made the difference between success and failure



### Case Study: Autologon64.exe and the Embedded Jump Table

Autologon64.exe presented a challenge that linear disassembly could not solve. The program crashed after patching, and investigation revealed a DISP32_TEXT_PTR instruction that our scanner never reached.

At address `0x4DBA`, we found a DISP32_TEXT_PTR instruction, preceded by a LEA that sets R9 to zero. The displacement is `0x4D6C`, based on what we learned earlier, this should be the start of an inline jump table in .text:

<img width="669" height="151" alt="image" src="https://github.com/user-attachments/assets/b9437796-6b47-4ec6-b171-d430d30a60b2" />

```asm
0x4DB3: lea r9, [rip - 0x4dba]        
0x4DBA: mov eax, dword ptr [r9 + r8*4 + 0x4d6c]  
0x4DC2: add r9, rax                  
0x4DCB: jmp r9                        
```


At address `0x4D6C`, there is indeed an inline jump table:

<img width="636" height="290" alt="image" src="https://github.com/user-attachments/assets/77b989a2-da5e-480d-b2be-cc3c657f9299" />

Let's create a mapping table for some of entries:

| Address | Byte | Mapped Instruction |
| --- | --- | --- | 
| 0x4D6C | DE 4D 00 00 | `RET` |
| 0x4D70 | DB 4D 00 00 | `MOV BYTE PTR [RCX-1], DL` |
| 0x4D74 | 07 4E 00 00 |  `MOV WORD PTR [RCX-2], DX`  |
| 0x4D78 | D7 4D 00 00 | `MOV WORD PTR [RCX-3], DX` |

The last valid instruction before the jump table is `ret` at `0x4D6B`. And there lies the problem: due to the oversight in the implementation (stop the disassembly at return-type instructions, but sometimes there are early returns in a function) at this version, linear disassembly stopped at this ret, never reaching the code block at `0x4DB0` where the `DISP32_TEXT_PTR` instruction resides.

<img width="783" height="502" alt="image" src="https://github.com/user-attachments/assets/c3d20b0f-05ba-4335-ac19-44f17395ef8d" />

The code block at `0x4DB0` is reachable—but only via a conditional branch from `0x4CB8`:

```
.text:0000000000004CA0 sub_4CA0        proc near               ; CODE XREF: sub_1000+4A↑p
.text:0000000000004CA0                                         ; sub_1850+2C↑p ...
.text:0000000000004CA0                 mov     r11, rcx
.text:0000000000004CA3                 movzx   edx, dl
.text:0000000000004CA6                 mov     r9, 101010101010101h
.text:0000000000004CB0                 imul    r9, rdx
.text:0000000000004CB4                 cmp     r8, 10h         ; switch 17 cases
.text:0000000000004CB8                 jbe     loc_4DB0
```

The Fix: We combine linear scanning with recursive disassembly to handle code blocks separated by embedded data. Starting from each function entry point (obtained from .pdata), we perform linear disassembly while tracking branch targets. When encountering a conditional branch like `jbe 0x4DB0` at `0x4CB8`, we add the target address to a visit queue. When we hit a `ret` or unconditional `jmp`, we stop the current path and pop the next address from the queue to continue scanning. This ensures all reachable code blocks are analyzed, even those following embedded data that linear disassembly alone would miss.

After resolving these challenges, Autologon64.exe finally ran properly.

### Similar Pattern, Different Fates

Autologon64.exe and DiskView64.exe were in the same test batch, and both contain DISP32_TEXT_PTR references with associated jump tables. We even encountered issues near two different jump tables in Autologon64.exe during testing. Before summarizing, let's compare three scenarios: two DISP32_TEXT_PTR references in Autologon64.exe and one in DiskView64.exe. Only the reference at 0x4DBA required recursive disassembly; for the others, linear disassembly alone was sufficient.

#### The Easy Win: DiskView64.exe (0xBFB0)

The DISP32_TEXT_PTR reference at `0xBFB0` is accessible via linear scanning because the reference precedes the jump table, which extends to the end of the function.
```
┌─────────────────────────────────────────────────────┐
│ 0xBF80: loc_BF80      ←────────────────┐            │ ← BF80: Start of jump code block
│ 0xBFA8: ja def_BFBA                    │            │
│ 0xBFAE: cdqe                           │            │
│ 0xBFB0: mov ecx, [rsi+rax*4+0xC388]    │            │ ← DISP32_TEXT_PTR (reachable)
│ 0xBFB7: add rcx, rsi                   │            │
│ 0xBFBA: jmp rcx                        │            │
│ ...                                    │            │
│ 0xC08E: jnz loc_BF80  ─────────────────┘            │ ← Branch to jump code block
│ ...                                                 │
│ 0xC381: jmp loc_C219                                │ ← Last instruction before jump table
│ 0xC386: align 8                                     │ ← Padding
│ 0xC388: [JUMP TABLE]                                │ ← Extends to end of function
└─────────────────────────────────────────────────────┘

```

#### The Lucky Escape: Autologon64.exe (0x4EDA)

The DISP32_TEXT_PTR reference at `0x4EDA` is also accessible because it precedes the jump table. However, unlike DiskView64.exe, the jump table does not extend to the end of the function, the case code blocks do. Technically, these case code blocks were not disassembled normally, since linear scanning cannot traverse the jump table to reach them. Fortunately, the case code blocks contain no references requiring updates, so this oversight had no practical impact. However, it remains a hidden risk: if any case code block contained a reference needing adjustment, the program would crash. This is an expected coincidence, as most case code is simple, consisting of value assignments and return instructions.

```
┌─────────────────────────────────────────────────────┐
│ 0x4E60: sub_4E60 proc                               │
│ 0x4E6A: jbe short loc_4ED0  ───────────┐            │
│ ...                                    │            │
│ 0x4ED0: loc_4ED0      ←────────────────┘            │ ← Jump code block
│ 0x4ED3: lea r9, cs:0                                │
│ 0x4EDA: mov ecx, [r9+r8*4+0x4EE7]                   │ ← DISP32_TEXT_PTR (reachable)
│ 0x4EE2: add rcx, r9                                 │
│ 0x4EE5: jmp rcx                                     │ ← Last instruction before jump table
│ 0x4EE7: [JUMP TABLE]                                │ ← Jump table in middle
│ ...                                                 │
| 0x4F30: [Case Code Area]                            │ ← No references (this time)
└─────────────────────────────────────────────────────┘

```

#### The Hard Lesson: Autologon64.exe (0x4DBA)

This case is the most challenging. The DISP32_TEXT_PTR reference at `0x4DBA` can only be reached via the conditional jump at `0x4CB8`. The `ret` instruction at `0x4D6B` stops linear disassembly, and the jump table lies between that return instruction and the jump code block. In this scenario, recursive disassembly is essential—linear scanning alone is insufficient.

```
┌─────────────────────────────────────────────────────┐
│ 0x4CA0: sub_4CA0 proc                               │
│ 0x4CB8: jbe loc_4DB0  ─────────────────────────┐    │ ← Branch to jump code block
│ ...                                            │    │
│ 0x4D68: mov rax, r11                           │    │
│ 0x4D6B: ret           ← Linear Disassembly Stop│    │
│ 0x4D6C: [JUMP TABLE]                           │    │ ← Jump table in middle
│         dd offset locret_4DDE                  │    │
│         dd offset loc_4DDB                     │    │
│         ... (17 entries)                       │    │
│ 0x4DB0: loc_4DB0      ←────────────────────────┘    │ ← Jump code block
│ 0x4DB3: lea r9, cs:0                                │
│ 0x4DBA: mov eax, [r9+r8*4+0x4D6C]                   │ ← DISP32_TEXT_PTR (only via branch)
│ 0x4DC2: add r9, rax                                 │
│ 0x4DCB: jmp r9                                      │
│ ...                                                 │
└─────────────────────────────────────────────────────┘
```


#### Side-by-Side Comparison

Finally, let's compare the 3 cases side by side:

| Case | Result | Cause |
| --- | --- | --- |
| DiskView64 (0xBFB0) | Linear sufficient| Jump code block precedes jump table; table at end of function |
| Autologon64 (0x4EDA) | Linear sufficient (hidden risk)| Jump code block precedes jump table; case code unreachable but has no references |
| Autologon64 (0x4DBA) | Recursive required | `ret` precedes jump table; jump code only reachable via branch |


### Summary: Choosing the Right Strategy

Neither pure linear scanning nor pure recursive scanning is sufficient on its own. Combining them appropriately is the right approach:

| Strategy | Handles | Cannot Handle |
|----------|---------|---------------|
| Linear | Contiguous code | Embedded data (jump tables), early return|
| Linear + Recursive | Code blocks separated by any data | (Comprehensive for our needs) |


## The Double-Update Family: When Two Subsystems Claim the Same Byte

The double-update problem—and its cousins in the multiple-update family—claimed several bugs during research and development. The principle itself is not difficult to understand; the challenge lies in predicting all the cases comprehensively:

- What types of references could be updated by more than one collector?
- When a new collector is added, how do we separate responsibilities clearly?

Let's explore them.

### The Superset Trap: When One Fix Covers Another

This category arises when fixing one reference type inadvertently fixes another. For example, the base relocation table contains all absolute addresses (64-bit VA). Some specialized reference types—such as Delay IAT entries—also contain absolute addresses, but they are already covered by the absolute address collector. The problem applies not only to absolute addresses but also to 32-bit RVAs, and beyond.

### Delay-Import Table: The Obvious Overlap

The well-known offensive security tool mimikatz.exe uses a delay-import table. Since the table contains absolute addresses pointing into .text, the first impression is to update them. Or do we need?

```
  Offset      Raw Bytes (little-endian)    Value (64-bit VA)      Target RVA                                                                                                                    
  ─────────────────────────────────────────────────────────────────────────────                                                                                                                 
  0x13DC30    20 86 0C 40 01 00 00 00      0x00000001400C8620     0xC8620                                                                                                                       
  0x13DC38    AB 86 0C 40 01 00 00 00      0x00000001400C86AB     0xC86AB                                                                                                                       
  0x13DC40    BD 86 0C 40 01 00 00 00      0x00000001400C86BD     0xC86BD                                                                                                                       
  0x13DC48    CF 86 0C 40 01 00 00 00      0x00000001400C86CF     0xC86CF                                                                                                                       
  0x13DC50    E1 86 0C 40 01 00 00 00      0x00000001400C86E1     0xC86E1                                                                                                                       
  ... 
```

From a completeness standpoint, the delay-import table is a distinct reference type deserving its own collector. However, the base relocation table is the superset—it contains all absolute addresses that need adjustment at load time, including those in the delay IAT. The relationship is straightforward, but let's examine a concrete data point.

We inserted 16 bytes of NOP into mimikatz.exe at address 0xC85FC. Within the affected range, the delay-load reference collector identified and fixed 30 entries. Then the absolute address collector (processing relocations) identified and updated 116 references. The result? Those same 30 delay IAT entries were updated twice.

| Aspect | Before Fix | After Fix | 
| --- | --- | --- |
|Absolute refs fixed| 116 | 86 | 
| Delay-load refs fixed | 30 | 30 |
| Overlap | 30 locations fixed twice | 0 (excluded from relocs)|
| IAT shift amount | +32 (wrong) |+16 (correct) |

The simplest solution would be to remove the delay IAT collector entirely, since the base relocation table already covers these addresses. However, to handle unexpected edge cases, we kept the dedicated collector and introduced a deduplication step instead. This way, each reference type has its own collector for logical completeness, while still avoiding duplicate updates.


### TLS and CFG: Same Story, Different Actors

TLS callback references share the same story as delay-load references: the absolute addresses of TLS callbacks are included in the base relocation table. This issue was identified while testing Autoruns64.exe.

CFG function references are absolute addresses as well. However, due to the complexity of the CFG table structure and its version-dependent format, the pragmatic solution is to simply disable CFG rather than attempt precise updates.


### UNWIND_INFO Handler vs Jump Table Entry: The Lookalike Problem

Exception handlers and UNWIND_INFO handlers are essentially 32-bit RVAs pointing to functions in .text. As listed in our Reference Type Taxonomy, these are subsets of the broader "Function Pointer (32-bit RVA)" category. Jump table entries share the same characteristic—they too are 32-bit RVAs pointing to code locations. This overlap created multiple double-update scenarios during development.

In the earlier stages of research, our jump table (in data sections) detection used a simple heuristic: scan data sections for sequences of multiple consecutive 32-bit values pointing into `.text` section. This approach was effective for finding switch-case tables, but it was too aggressive—it also matched UNWIND_INFO structures.

The problem: UNWIND_INFO handlers are 32-bit RVAs pointing to exception handling code in .text. When multiple UNWIND_INFO structures are laid out consecutively in memory, their handler RVAs form a sequence that looks remarkably like a jump table in data sections. The result was double-update: the same handler RVA was fixed once by unwind handler collector and again by jump table collector. The fix was straightforward—we built an exclusion list of UNWIND_INFO regions and skipped them during jump table scanning.


### Inline Jump Table: The Subtle Sibling
A more subtle double-update emerged after we implemented the DISP32_TEXT_PTR collector. Recall the inline jump table pattern:

```asm
0x4DBA: mov eax, [r9 + r8*4 + 0x4D6C]  ; DISP32_TEXT_PTR (displacement = 0x4D6C)
        ...
0x4D6C: dd 0x4DDE, 0x4DDB, 0x4E07, ... ; Jump table entries at 0x4D6C
```
Here, `0x4D6C` is both:
- The displacement value in the DISP32_TEXT_PTR instruction (needs update)
- The location of jump table entries (each entry also needs update)

In our initial implementation, the DISP32_TEXT_PTR collector was designed to handle both: it updated the displacement and collected the inline jump table entries at that location. Shortly after, we also implemented a dedicated inline jump table collector that scanned .text for these same entries. Neither collector knew about the other's work.

As a result, when testing a game client with 320 bytes of NOP inserted to the entry point, inline jump table entries were collected twice and shifted twice (+640 instead of +320).

### Summary

In Chapter 6, we presented reference types as a flat taxonomy—each type listed independently with its detection source, fix method, and guardrails to avoid misdetection. However, within such a flat categorization, certain reference types have superset-subset relationships. Additionally, even without a strict superset-subset hierarchy, there can be overlap, or the boundaries may blur if detection and guardrails are not robust enough.

Despite this complexity, we prioritize completeness over elegance. We would rather have multiple collectors identify the same reference (and deduplicate later) than risk missing a reference entirely. A single missed reference means a crash; a duplicate detection is merely an engineering problem with a straightforward solution.

The hierarchy below reveals the true relationships:

```
64-bit VA:
└── Base Relocation (.reloc)  
    ├── Delay IAT            
    ├── TLS Callbacks       
    └── CFG Entries           

32-bit RVA:
└── Function Pointer (heuristic)
    ├── Jump Table Entry (data sections)
    ├── Jump Table Entry (.text section)
    └── UNWIND_INFO Handler  
```

The Golden Rule: Collect specialized references first, then exclude their locations from superset collectors.


## Short Jump Overflow: The Chain Reaction We Detected But Didn't Defuse

Short jump overflow is a challenge we anticipated from the very early stages of research and development. However, we still have not implemented a fix. More accurately, we added detection but chose not to fix it.

The rel8 encoding is used for short jumps, with a range of `±127` bytes. When code shifts exceed this range, the instruction must be extended to `rel16 (±32KB)` or `rel32 (±2GB)`. The challenge is that this extension itself adds bytes, and those additional bytes can trigger further overflows in a chain reaction. The chain reaction is theoretically unbounded: each expansion adds bytes, which enlarges the affected range, which may catch more short jumps, which require more expansions. Predicting the final byte count becomes a complex fixed-point computation.

To implement automatic expansion, the following requirements should be met:
- Iterative recalculation — Repeatedly expand and recalculate until no more overflows occur
- Instruction rewriting — Replace 2-byte jmp short (EB xx) with 5-byte jmp near (E9 xx xx xx xx)
- Cascading reference updates — All references must be recalculated after each expansion

Additionally, the segmented absorption algorithm processes zones from back to front. If an overflow is triggered mid-way—say, at Zone 3 after Zones 4 and 5 have already been shifted—the situation becomes extremely difficult to recover from. Do we restart from Zone 5? But the data has already been modified. Do we continue forward with adjusted calculations? But every subsequent zone's shift amount has now changed. Each overflow triggers this cascade of recalculations, and any oversight corrupts the file. The bookkeeping complexity grows exponentially with each overflow event.

The complexity is significant. Fortunately, it can be mitigated as long as we understand the context of the insertion location and insert wisely, rather than grabbing a random address and inserting a meaninglessly large number of bytes.

It is also reassuring to know that across 78 real-world test programs of varying categories, types, and sizes, we encountered zero short jump overflow cases. Two factors explain this:
1. Compiler behavior — Modern compilers (especially MSVC) favor rel32 even for short distances, reserving rel8 only for very tight loops or hand-optimized code
2. Segmented Absorption — Our algorithm limits the blast radius; by distributing shifts across padding zones, no single region experiences catastrophic displacement




# The Proving Ground: Famous and Infamous Programs

Throughout the research and development process, we continuously tested against real-world programs to ensure our in-place insertion technique is practical and applicable beyond controlled laboratory conditions. No synthetic or toy programs were used. Across different development phases, 78 programs underwent multiple testing rounds—each major algorithm update triggered a full regression test.
The test corpus comprises:

- Sysinternals suite — Microsoft's widely-adopted system utilities
- Windows built-in binaries — Including calc.exe
- Security tools — Process Hacker, PE Bear, and mimikatz.exe
- Commercial game software — A complete server cluster (login server, lobby server, management server, channel server, game server) plus the game client

The corpus spans CLI, console, and GUI applications, with file sizes ranging from under 100KB to over 7MB.

## Evaluation Philosophy

Our selection criteria prioritized diversity, real-world relevance, and verifiability:

### Sysinternals Suite (68 programs)
The Sysinternals collection alone covers a broad spectrum of categories, complexities, and sizes. These tools are compiled and distributed by Microsoft, lending credibility that self-compiled samples cannot provide. Many are industry standards—PsExec64.exe, for instance, appears in countless penetration testing workflows and incident response playbooks. If our technique breaks Sysinternals tools, it breaks tools that practitioners actually use.

### Windows Built-in Utilities
Calc.exe serves a specific role: at under 50KB with a full GUI, it represents the minimal viable graphical application. Its simplicity makes it an effective sanity check—if insertion fails here, something is fundamentally wrong.

### Security Tools
Process Hacker and PE Bear occupy a unique position: they are complex applications whose correctness is immediately verifiable. Unlike a generic utility where subtle corruption might go unnoticed, these tools perform intricate operations—parsing PE structures, enumerating processes, analyzing memory. Any corruption surfaces quickly during normal use. They also represent software familiar to our target audience.

### Commercial Game Software
The game components introduce challenges absent from utility software: multi-tier architecture with interdependent server processes, proprietary protocols, and a heavyweight client. The client binary approaches 8MB, renders graphics via DirectX, and consumes over 5GB of RAM at runtime. This is not a controlled experiment—it is commercial software operating under production-like conditions. Details are masked as these binaries originate from leaked sources.


## Test Configuration
The standard test configuration inserted `640` bytes of NOP at each program's entry point. This setting is deliberately aggressive:

- For reverse engineers: 640 bytes far exceeds typical patching needs. Flipping a conditional branch requires 2-6 bytes; injecting a small hook requires 20-50 bytes. 640 bytes is overkill by an order of magnitude.
- For red teamers: Staged shellcode for common C2 frameworks (Cobalt Strike, Metasploit, Sliver, etc.) typically requires 300-400 bytes. 640 bytes comfortably accommodates any standard payload.
- For stress testing: Inserting at the entry point is particularly demanding. The CRT entry point region contains densely-packed metadata—TLS callbacks, security cookie initialization, exception handler registration. Shifting 640 bytes here propagates displacement through critical initialization structures.

For programs with insufficient internal padding to absorb 640 bytes, we tested at their maximum feasible insertion size—typically the largest value that the Segmented Absorption Algorithm could accommodate without exceeding available breadcrumbs.

Exhaustively testing every code path is impractical—not only due to time constraints, but also environmental dependencies. ADExplorer requires Active Directory; network utilities need specific server configurations; kernel tools demand particular driver states. Our pass criteria therefore focused on observable behavior: no crashes or hangs, correct display and output, and successful execution of core functionality under accessible test conditions.

In summary, our test configuration is both practical and strict. We did not cherry-pick favorable insertion points or modest byte counts. The results reflect what practitioners would encounter when applying this technique to real targets.

## The Test Pyramid

Among the test samples, some pose higher difficulty than others—particularly those with larger size, GUI complexity, or intricate runtime behavior.

The table below outlines each tier along with representative examples:

| Tier | Characteristics | Examples |
| --- | --- | --- |
| Trivial | Simple, minimal CLI programs | psping64, strings64, ru64 |
| Medium | Larger CLI/console programs, small GUI apps | mimikatz, procdump64, calc.exe, ADExplorer64 |
| High | Large CLI/console programs, medium-to-large GUI apps | Sysmon64, game server, procexp64, CPUSTRES64 |
| Nightmare | Largest GUI programs with complex features; stress test targets | Game Client |

## Test Results

The table captures the test results for all programs.

| Program | Description | Subsystem | Size | Result|
|--------|-------------|---------|------|-----------|
| accesschk64.exe | sysinternals | CLI | 792KB |   PASS |
| ADExplorer64.exe | sysinternals | GUI | 647KB |   PASS |
| ADInsight64.exe | sysinternals | GUI | 1.68MB |   PASS |
| adrestore64.exe | sysinternals | CLI | 441KB |   PASS |
| Autologon64.exe | sysinternals | GUI | 431KB |   PASS |
| Autoruns64.exe | SysInternals | GUI | 1.86MB |   PASS |
| autorunsc64.exe | SysInternals | CLI | 768KB |   PASS |
| Bginfo64.exe | SysInternals | GUI | 2.64MB |   PASS |
| Cacheset64.exe | SysInternals | GUI | 545KB |   PASS |
| Clockres64.exe | SysInternals | CLI | 430KB |   PASS |
| Contig64.exe | SysInternals | CLI | 279KB |   PASS |
| Coreinfo64.exe | SysInternals | CLI | 486KB |   PASS |
| CoreinfoEx64.exe | SysInternals | GUI | 989KB |   PASS |
| CPUSTRES64.EXE | SysInternals | GUI | 2.72MB |   FAIL AT 177 |
| dbgview64.exe | SysInternals | GUI | 1.05MB |   PASS |
| Desktops64.exe | SysInternals | NA | 213KB |   PASS |
| disk2vhd64.exe | SysInternals | GUI | 1.37MB |   FAIL AT 398 |
| diskext64.exe | SysInternals | CLI | 433KB |   PASS |
| Diskmon64.exe | SysInternals | GUI | 620KB |   PASS |
| DiskView64.exe | SysInternals | GUI | 504KB |   PASS |
| du64.exe | SysInternals | CLI | 455KB |   PASS |
| FindLinks64.exe | SysInternals | CLI | 190KB |   PASS |
| handle64.exe | SysInternals | CLI | 407KB |   PASS |
| hex2dec64.exe | SysInternals | CLI | 508KB |   PASS |
| junction64.exe | SysInternals | CLI | 438KB |   FAIL AT 157 |
| Listdlls64.exe | SysInternals | CLI | 216KB |   PASS |
| livekd64.exe | SysInternals | CLI | 604KB |   PASS |
| LoadOrd64.exe | SysInternals | GUI | 473KB |   PASS |
| LoadOrdC64.exe | SysInternals | CLI | 470KB |   PASS |
| logonsessions64.exe | SysInternals | CLI | 550KB |   PASS |
| movefile64.exe | SysInternals | CLI | 430KB |   PASS |
| notmyfault64.exe | SysInternals | GUI | 348KB |   PASS |
| notmyfaultc64.exe | SysInternals | CLI | 1.03MB |   PASS |
| ntfsinfo64.exe | SysInternals | CLI | 156KB |   PASS WITH 420 |
| pendmoves64.exe | SysInternals | CLI | 431KB |   PASS |
| pipelist64.exe | SysInternals | CLI | 432KB |   PASS |
| procdump64.exe | SysInternals | CLI | 705KB |   PASS |
| procexp64.exe | SysInternals | GUI | 2.29MB |   PASS |
| Procmon64.exe | SysInternals | GUI | 2.04MB |   PASS |
| PsExec64.exe | SysInternals | CLI | 814KB |   PASS |
| psfile64.exe | SysInternals | CLI | 283KB |   PASS |
| PsGetsid64.exe | SysInternals | CLI | 495KB |   PASS |
| PsInfo64.exe | SysInternals | CLI | 524KB |   PASS |
| pskill64.exe | SysInternals | CLI | 466KB |   PASS |
| pslist64.exe | SysInternals | CLI | 261KB |   PASS |
| PsLoggedon64.exe | SysInternals | CLI | 167KB |   PASS WITH 320 |
| psloglist64.exe | SysInternals | CLI | 370KB |   FAIL: NO OUTPUT AT 398 |
| pspasswd64.exe | SysInternals | CLI | 265KB |   PASS |
| psping64.exe | SysInternals | CLI | 339KB |   PASS |
| PsService64.exe | SysInternals | CLI | 315KB   | PASS |
| RAMMap64.exe | SysInternals | GUI | 355KB |   FAIL AT 357 |
| RegDelNull64.exe | SysInternals | CLI | 444KB |   PASS |
| ru64.exe | SysInternals | CLI | 440KB |   PASS |
| sdelete64.exe | SysInternals | CLI | 219KB |   PASS |
| ShareEnum64.exe | SysInternals | GUI | 629KB |   PASS |
| sigcheck64.exe | SysInternals | CLI | 529KB |   PASS |
| streams64.exe | SysInternals | CLI | 434KB |   PASS |
| strings64.exe | SysInternals | CLI | 467KB |   PASS |
| sync64.exe | SysInternals | CLI | 435KB |   PASS |
| Sysmon64.exe | SysInternals | CLI | 4.35MB |   PASS |
| tcpvcon64.exe | SysInternals | CLI | 245KB |   PASS |
| tcpview64.exe | SysInternals | GUI | 1.03MB |   PASS |
| Testlimit64.exe | SysInternals | CLI | 239KB   | PASS |
| vmmap64.exe | SysInternals | GUI | 2.62MB |   PASS |
| Volumeid64.exe | SysInternals | CLI | 166KB |   PASS WITH 480 |
| whois64.exe | SysInternals | CLI | 512KB |   PASS |
| Winobj64.exe | SysInternals | GUI | 1.69MB |   PASS |
| ZoomIt64.exe | SysInternals | GUI | 906KB |   PASS |
| Game Server | Game Server | Console | 4.82MB |   PASS |
| Mgmt Server | Game Server | Console | 596KB  | PASS |
| Tool Server | Game Server | Console | 623KB | PASS |
| Login Server | Game Server | Console | 296KB   | PASS |
| Lobby Server | Game Server | Console | 375KB   | PASS |
| Game Client | Game Client | GUI | 7.57MB   | PASS |
| Calc | Windows Binary | GUI | 48KB   | PASS |
| Process Hacker | Security Tool | GUI | 1.63MB   | PASS |
| PE Bear | Security Tool | GUI | 5.17MB   | PASS |
| mimikatz.exe | Security Tool | Console | 1.29 MB | PASS |

## The ScoreBoard
73 out of 78 programs passed with 640 bytes (or near-maximum available breadcrumbs) inserted. Pass rate: 93.6%.

Five programs reached boundary conditions before 640 bytes:

| Program | Maximum Sage Insertion |
| --- | --- |
| junction64.exe | 156 bytes |
| CPUSTRES64.EXE | 176 bytes |
| RAMMap64.exe | 356 bytes |
| psloglist64.exe | 397 bytes |
| disk2vhd64.exe | 397 bytes |

However, all five still accommodate `150+` bytes. At this threshold, `100%` of programs pass.

Interestingly, the "nightmare" challenge—the 7.57MB game client with 5GB+ RAM usage at runtime—succeeded without issue, while the seemingly simple 438KB CLI tool junction64.exe hit its boundary at just 156 bytes. This counterintuitive result highlights that failures stem from specific edge cases in code layout, not overall program complexity.

## Stress Test: PE Bear Loads Itself

Though we successfully patched the game client, we prefer to mask those details given its origin. Instead, we demonstrate with PE Bear—the second-largest GUI program in our corpus at 5.17MB. And for this particular sample, we go a step further: we use real shellcode that displays a message box to show the technique’s practical viability:

```powershell
python messagebox_shellcode.py -s 640 -o msg.bin
============================================================
  Windows x64 MessageBox Shellcode Generator
  Author: Senzee
============================================================
[+] Assembled: 154 instructions, 429 bytes
[+] Padded: +211 NOPs = 640 bytes
[+] Saved: msg.bin
```

The shellcode itself is 429 bytes, padded with NOPs to reach a total size of 640 bytes.

After inserting those 640 bytes at the program’s entry point, we launched the patched PE Bear—and a message box appeared immediately.

<img width="998" height="703" alt="image" src="https://github.com/user-attachments/assets/77f72ffc-396c-40cf-a23b-15b4053a5b17" />


After confirming the message box, PE Bear continues running normally. We then load the patched binary into PE Bear itself for analysis. The result is reassuring: it correctly parses its own modified headers, displays all sections, resolves imports, and reports no anomalies. A self‑referential proof of correctness.


<img width="1783" height="1214" alt="image" src="https://github.com/user-attachments/assets/1faff1c9-aa1c-4368-96c0-32d7b570e05a" />


<img width="1783" height="1220" alt="image" src="https://github.com/user-attachments/assets/468377ca-29b9-4a86-b625-eda57d4740eb" />



## Summary
For in-scope programs—non-obfuscated, non-packed, MSVC-compiled x64 PE binaries—our in-place insertion technique is reliable and practical. It survived the gauntlet: 78 real-world programs spanning utilities, security tools, and commercial game software. The `93.6%` success rate at `640` bytes, and `100%` success rate at `150+` bytes, demonstrates that this is not a laboratory curiosity but a deployable technique.

# The Pragmatist's Manifesto: Strategic Omissions

No tool handles everything. The question is not whether gaps exist, but whether they matter in practice. This chapter documents what we deliberately left unimplemented—and why.

## Short Jump Auto-Expansion: Complexity Not Worth the Risk

Short jumps (rel8, ±127 bytes) can overflow when code shifts push their targets beyond range, as discussed in Chapter 7. The theoretically correct remedy is to auto‑promote them to near jumps (rel32), but that approach cascades: each promotion increases instruction size, which may in turn overflow other short jumps, forcing repeated recalculation until the system stabilizes.

Our implementation detects this condition but does not attempt to correct it. When an overflow is identified, the tool simply reports “not feasible.” This is an intentional design choice. Implementing full expansion logic requires complex iterative algorithms, careful handling of circular dependencies, and safeguards against non‑terminating adjustment loops—while the Segmented Absorption Algorithm already keeps shift distances small enough that overflows are uncommon.

Risk can be mitigated further through informed insertion strategy: understanding the binary’s layout, selecting insertion points in regions with few short jumps, and inserting only the bytes actually required rather than large, arbitrary blocks. If a reverse engineer needs 8 bytes to flip a conditional, they should insert 8 bytes—not 640. Thoughtful, context‑aware insertion avoids the overflow scenarios that indiscriminate bulk insertion tends to provoke.

Across 78 test programs—each subjected to an intentionally extreme 640‑byte insertion at the entry point—we observed zero short‑jump overflows. With disciplined insertion practices, the likelihood becomes even lower.

## MSVC C++ Exception Handling: The Hidden RVA Forest

Beyond the UNWIND_INFO handler pointers we already update, MSVC’s full C++ exception handling machinery introduces additional metadata structures that also embed RVAs and code-relative references, such as:
- FuncInfo — Describes the exception-handling state machine for a function
- TryBlockMapEntry — Encodes the start/end ranges of try regions
- IPtoStateMapEntry — Maps instruction addresses to EH state transitions
- UnwindMapEntry — Describes stack-unwinding actions for destructors

These tables are deeply nested, highly compiler-version dependent, and involve a mixture of RVAs, relative offsets, and indirect pointer chains. Correctly rewriting them requires traversing multiple layers of metadata (e.g., `FuncInfo → TryBlockMap → HandlerType → CatchableTypeArray`) with layouts that differ across MSVC releases and optimization modes.

Current behavior: BinaryScalpel updates only the unwind handler RVAs reachable through `.pdata / UNWIND_INFO`. Full MSVC C++ EH metadata rewriting is not currently implemented.

Impact: If a C++ exception is thrown from within a shifted region, and the runtime consults corrupted EH tables, exception dispatch or unwinding could behave incorrectly (e.g., selecting the wrong handler or failing during cleanup). In practice, this risk requires several conditions to coincide:
- The binary is compiled with C++ exception handling enabled
- An exception is actually thrown across the shifted code region
- The execution path relies on the affected EH metadata during unwinding

Many system utilities—often written in C, or using exceptions sparingly—rarely satisfy these conditions, which is why this remains a lower-priority edge case for the current scope.


## RTTI: The dynamic_cast Tax

C++ Run-Time Type Information (RTTI) supports dynamic_cast and typeid through a hierarchy of compiler-generated structures, including:
- RTTICompleteObjectLocator — Referenced via `vftable[-1]`
- RTTIClassHierarchyDescriptor — Describes inheritance relationships
- RTTIBaseClassDescriptor — Per-base-class metadata
- RTTITypeDescriptor — Type name and associated `type_info` object

Current behavior: RTTI-related metadata is not currently rewritten.

Impact: In binaries that rely heavily on RTTI, shifting code or associated tables without updating these structures could lead to incorrect `dynamic_cast` results or runtime faults during type resolution. However, RTTI is frequently disabled in performance-sensitive builds (`/GR-`), and many system-style executables make little or no use of dynamic_cast.

Importantly, the most security- and execution-critical component—the vtable’s function pointer dispatch—is already covered by relocation-backed pointer handling. RTTI support remains an area for future extension rather than a core requirement for typical in-scope targets.


## The Meta-Lesson: Knowing When NOT to Fix
These three features share a common pattern: high implementation complexity, high regression risk, and low observed impact.

Across 78 real‑world programs we tested—including security tools, system utilities, and a commercial game client—none showed crashes or irregular behavior that could be traced to these omissions. In practice, the programs either do not rely on these features, do not exercise them in the modified regions, or use them in ways that remain stable after our changes.

This raises a pragmatic question: is the fix worth the risk?

Every new collector introduces potential for regression bugs. The double-update family (Chapter 7) taught us this lesson repeatedly—adding a handler for one reference type can corrupt another if boundaries aren't carefully maintained. For features that cause zero observed failures across a diverse test corpus, the calculus is clear: the risk of introducing new bugs outweighs the benefit of fixing theoretical edge cases.

We chose to document these omissions openly rather than pursue completeness for its own sake. A tool that handles 93.6% of cases reliably is more useful than one that aims for 100% and behaves unpredictably.

Knowing what to build reflects intelligence. Knowing what to leave out reflects wisdom.


# The Payoff: Who Benefits and How

## For the Reverse Engineer

Reverse engineers often need only a handful of bytes to get the job done: flip a conditional jump, bypass a license check, or disable an anti-debug routine. In many cases, overwriting existing instructions is enough. But when it isn’t—when the byte budget is simply too tight—the available alternatives become wildly disproportionate to the problem.

Creating a new section or hunting for code caves just to gain 4–16 bytes is like deploying a forklift to move a chair. Trampolines add even more friction: execution jumps away, performs the patch logic elsewhere, then returns. This breaks local continuity, complicates debugging, and makes the patch harder to reason about. The fix no longer lives where the problem lives.

In-place insertion restores the missing convenience. The injected bytes appear exactly where they are needed, preserving local context, readability, and control-flow coherence. For the reverse engineer who simply needs a few extra bytes of space, this is the capability that tools have lacked for decades.

## For Offensive Security Practitioner

Offensive security operates under a different set of constraints: payload delivery, persistence, and evasion. Here, the limiting factor is not whether insertion is possible, but how detectable the modification becomes.

Adding a new section leaves unmistakable artifacts: altered PE headers, additional section entries, and structural anomalies that defenders can flag immediately. Code-cave hunting avoids some of these traces, but introduces others. Caves large enough for staged payloads are uncommon in .text, and borrowing space from .data or .rdata often requires changing section permissions—another high-signal indicator. Worse, “unused” bytes may not be unused at runtime.

In-place insertion provides a cleaner alternative. No new sections. No characteristic changes. No trampoline overhead. The payload remains within the original .text boundaries, integrated into existing compiler-generated layout. Integrity checks will break regardless—one byte is enough to invalidate a signature—but among practical options, in-place insertion offers the smallest footprint and the most controlled disturbance.

The goal is not perfect stealth. The goal is to raise the cost of detection. When a modified binary retains its normal structure, defenders must dig deeper to find what changed—and that additional effort has real operational value.


# Conclusion: Drawing the Real Boundary

The desire for in-place byte insertion is not new. Forum threads going back more than a decade ask the same question: why can’t I just insert a few bytes? The concept feels obvious, almost trivial—yet the implementation is anything but.

For years, the problem was acknowledged and then avoided. Too fragile. Too many hidden references. Too much engineering risk. Tools offered workarounds—trampolines, code caves, new sections—but none addressed the underlying gap.

This research breaks that silence.

We do not claim a universal solution to binary rewriting. We do not handle packed binaries, managed code, or every compiler ecosystem. But within a practical and widely relevant scope—non-obfuscated, MSVC-compiled x64 PE executables—we achieve a 93.6% success rate across 78 real-world programs, with consistent reliability for insertion sizes that matter in practice.

This is not a theoretical exercise. It is a deployable technique validated against binaries practitioners actually encounter.

The core contributions are:
- Segmented Absorption Algorithm — Distributes displacement across internal padding regions, containing the blast radius and reducing the number of references that require adjustment. It transforms a global rewriting problem into a localized and tractable one.
- DISP32_TEXT_PTR Reference Type — A previously undocumented class of .text-pointing displacement operands that hide in plain sight and silently corrupt execution when overlooked.
- Hybrid Disassembly Strategy — Neither pure linear nor pure recursive scanning is sufficient. Combining both captures reference patterns that either approach alone would miss.

These are not implementation details—they are the conceptual tools that make true in-place insertion possible. The tool is an artifact; the insight is the contribution.

We also acknowledge the remaining boundaries. Short-jump chain reactions are detected but not resolved. MSVC C++ exception metadata beyond UNWIND_INFO is not rewritten. RTTI structures remain untouched. These omissions are documented rather than concealed—and across our corpus, none produced observable failures. Future work may extend coverage and uncover edge cases not yet encountered.

Our hope is that this research serves as a foundation. We have charted the terrain: where in-place insertion works, where it falters, and why. We invite others to extend the map—support additional compilers, architectures, and the edge cases beyond our current boundary.

The question “Why can’t I just insert a few bytes?” finally has an answer.

Not a workaround.
Not a compromise.
A real answer.


# Appendix

## Tool Usage Quick Reference

### BinaryScalpel.py

Both the Python and C# versions share essentially the same command‑line arguments and usage pattern:

```bash
# Validate whether the specified PE file is likely to fall within scope.
python BinaryScalpel.py target.exe --validate

# List available code caves, optionally filtered by section, and return the top N by size.
python BinaryScalpel.py target.exe --list-caves --cave-top 5 --cave-section text

# Analyze the insertion impact (Method 3) at the specified address and byte size — analysis only.
python BinaryScalpel.py target.exe -m 3 -a 0x1050 -s 8

# Analyze with debug output (shows detected references)
python BinaryScalpel.py target.exe -m 3 -a 0x1050 -s 8 --debug

# Test mode: insert N NOP bytes for quick validation. If no address is provided, the entry point is used as the default insertion location
python BinaryScalpel.py target.exe -m 3 -a 0x1050 -n 16 -o patched.exe

# Perform actual insertion with hex bytes
python BinaryScalpel.py target.exe -m 3 -a 0x1050 -x "9090909090909090" -o patched.exe

# Perform actual insertion with assembly code
python BinaryScalpel.py target.exe -m 3 -a 0x1050 -c "nop; nop; nop; nop" -o patched.exe

# Perform actual insertion with a binary file
python BinaryScalpel.py target.exe -m 3 -a 0x1050 -b msg.bin -o patched.exe
```





### messagebox_shellcode.py

Generate shellcode that displays a message box, then pad it with NOPs to a total size of `640` bytes:

```powershell
python messagebox_shellcode.py -s 640 -o msg.bin
============================================================
  Windows x64 MessageBox Shellcode Generator
  Author: Senzee
============================================================
[+] Assembled: 154 instructions, 429 bytes
[+] Padded: +211 NOPs = 640 bytes
[+] Saved: msg.bin

# Python Format
buf =  b"\x9c\x50\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55"
buf += b"\x41\x56\x41\x57\x48\x89\xe5\x48\x83\xe4\xf0\x48\x83\xec\x20\x48\x31\xd2\x65\x48"
buf += b"\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d\x8b\x09\x4d\x8b\x49"
buf += b"\x20\x41\xb8\x8e\x4e\x0e\xec\xe8\x00\x01\x00\x00\x48\x85\xc0\x0f\x84\xda\x00\x00"
buf += b"\x00\x49\x89\xc4\x48\x83\xec\x20\x48\x89\xe1\xc6\x01\x75\xc6\x41\x01\x73\xc6\x41"
buf += b"\x02\x65\xc6\x41\x03\x72\xc6\x41\x04\x33\xc6\x41\x05\x32\xc6\x41\x06\x2e\xc6\x41"
buf += b"\x07\x64\xc6\x41\x08\x6c\xc6\x41\x09\x6c\x31\xc0\x88\x41\x0a\x48\x83\xec\x20\x41"
buf += b"\xff\xd4\x48\x83\xc4\x40\x48\x85\xc0\x0f\x84\x90\x00\x00\x00\x49\x89\xc1\x41\xb8"
buf += b"\xa8\xa2\x4d\xbc\xe8\x9f\x00\x00\x00\x48\x85\xc0\x74\x7d\x49\x89\xc5\x48\x83\xec"
buf += b"\x20\x48\x89\xe1\xc6\x01\x42\xc6\x41\x01\x69\xc6\x41\x02\x6e\xc6\x41\x03\x61\xc6"
buf += b"\x41\x04\x72\xc6\x41\x05\x79\xc6\x41\x06\x53\xc6\x41\x07\x63\xc6\x41\x08\x61\xc6"
buf += b"\x41\x09\x6c\xc6\x41\x0a\x70\xc6\x41\x0b\x65\xc6\x41\x0c\x6c\x31\xc0\x88\x41\x0d"
buf += b"\x49\x89\xc8\x48\x83\xec\x10\x48\x89\xe1\xc6\x01\x53\xc6\x41\x01\x75\xc6\x41\x02"
buf += b"\x63\xc6\x41\x03\x63\xc6\x41\x04\x65\xc6\x41\x05\x73\xc6\x41\x06\x73\xc6\x41\x07"
buf += b"\x21\x88\x41\x08\x48\x89\xca\x45\x31\xc9\x31\xc9\x48\x83\xec\x20\x41\xff\xd5\x48"
buf += b"\x89\xec\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5d\x5f"
buf += b"\x5e\x5a\x59\x5b\x58\x9d\xeb\x65\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01"
buf += b"\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01"
buf += b"\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31"
buf += b"\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45"
buf += b"\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b"
buf += b"\x04\x8b\x4c\x01\xc8\xc3\x31\xc0\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
buf += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"

[+] Final size: 640 bytes

[*] Testing...
[+] Loaded at: 0x277a68c0000
```

# Reference

<https://stackoverflow.com/questions/67564730/ida-patching-how-to-add-new-code-create-new-variable> 

<https://reverseengineering.stackexchange.com/questions/26530/what-are-my-options-to-add-instructions-to-a-binary> 

<https://www.ired.team/offensive-security/code-injection-process-injection/backdooring-portable-executables-pe-with-shellcode>

<https://captmeelo.com/exploitdev/2018/07/21/backdoor101-part2.html> 

<https://pentest.blog/art-of-anti-detection-2-pe-backdoor-manufacturing/> 

<https://0xrick.github.io/win-internals/pe7/>

<https://llvm.org/doxygen/WinException_8cpp_source.html>

<https://cel.cs.brown.edu/crp/idioms/rtti.html>

<https://github.com/ojdkbuild/tools_toolchain_vs2017bt_1416/blob/master/VC/Tools/MSVC/14.16.27023/crt/src/vcruntime/rtti.cpp>



