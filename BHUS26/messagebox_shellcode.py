#!/usr/bin/env python3


import ctypes
import sys

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
except ImportError:
    print("Error: keystone-engine not installed")
    sys.exit(1)


def generate_shellcode_asm():

    
    CODE = (
        # ============================================
        # PROLOGUE: Save all registers and flags
        # ============================================
        "_start:"
        "   pushfq;"
        "   push rax;"
        "   push rbx;"
        "   push rcx;"
        "   push rdx;"
        "   push rsi;"
        "   push rdi;"
        "   push rbp;"
        "   push r8;"
        "   push r9;"
        "   push r10;"
        "   push r11;"
        "   push r12;"
        "   push r13;"
        "   push r14;"
        "   push r15;"
        
        "   mov rbp, rsp;"
        "   and rsp, 0xFFFFFFFFFFFFFFF0;"
        "   sub rsp, 0x20;"
        
        # ============================================
        # Find kernel32.dll via PEB (使用原版方式)
        # ============================================
        "find_kernel32:"
        "   xor rdx, rdx;"
        "   mov rax, gs:[rdx+0x60];"       # PEB
        "   mov rsi, [rax+0x18];"          # Ldr
        "   mov rsi, [rsi+0x20];"          # InMemoryOrderModuleList
        "   mov r9, [rsi];"                # First -> exe
        "   mov r9, [r9];"                 # Second -> ntdll
        "   mov r9, [r9+0x20];"            # Third -> kernel32 base
        
        # ============================================
        # Get LoadLibraryA (hash = 0xEC0E4E8E)
        # ============================================
        "   mov r8d, 0xEC0E4E8E;"
        "   call parse_module;"
        "   test rax, rax;"
        "   jz epilogue;"
        "   mov r12, rax;"                 # R12 = LoadLibraryA
        
        # ============================================
        # Build "user32.dll" on stack
        # ============================================
        "   sub rsp, 0x20;"
        "   mov rcx, rsp;"
        "   mov byte ptr [rcx], 0x75;"     # u
        "   mov byte ptr [rcx+1], 0x73;"   # s
        "   mov byte ptr [rcx+2], 0x65;"   # e
        "   mov byte ptr [rcx+3], 0x72;"   # r
        "   mov byte ptr [rcx+4], 0x33;"   # 3
        "   mov byte ptr [rcx+5], 0x32;"   # 2
        "   mov byte ptr [rcx+6], 0x2e;"   # .
        "   mov byte ptr [rcx+7], 0x64;"   # d
        "   mov byte ptr [rcx+8], 0x6c;"   # l
        "   mov byte ptr [rcx+9], 0x6c;"   # l
        "   xor eax, eax;"
        "   mov byte ptr [rcx+0xa], al;"   # null
        
        "   sub rsp, 0x20;"
        "   call r12;"                     # LoadLibraryA("user32.dll")
        "   add rsp, 0x40;"
        "   test rax, rax;"
        "   jz epilogue;"
        "   mov r9, rax;"                  # R9 = user32.dll base
        
        # ============================================
        # Get MessageBoxA (hash = 0xBC4DA2A8)
        # ============================================
        "   mov r8d, 0xBC4DA2A8;"
        "   call parse_module;"
        "   test rax, rax;"
        "   jz epilogue;"
        "   mov r13, rax;"                 # R13 = MessageBoxA
        
        # ============================================
        # Call MessageBoxA
        # ============================================
        # Caption "BinaryScalpel"
        "   sub rsp, 0x20;"
        "   mov rcx, rsp;"
        "   mov byte ptr [rcx], 0x42;"     # B
        "   mov byte ptr [rcx+1], 0x69;"   # i
        "   mov byte ptr [rcx+2], 0x6e;"   # n
        "   mov byte ptr [rcx+3], 0x61;"   # a
        "   mov byte ptr [rcx+4], 0x72;"   # r
        "   mov byte ptr [rcx+5], 0x79;"   # y
        "   mov byte ptr [rcx+6], 0x53;"   # S
        "   mov byte ptr [rcx+7], 0x63;"   # c
        "   mov byte ptr [rcx+8], 0x61;"   # a
        "   mov byte ptr [rcx+9], 0x6c;"   # l
        "   mov byte ptr [rcx+0xa], 0x70;" # p
        "   mov byte ptr [rcx+0xb], 0x65;" # e
        "   mov byte ptr [rcx+0xc], 0x6c;" # l
        "   xor eax, eax;"
        "   mov byte ptr [rcx+0xd], al;"
        "   mov r8, rcx;"                  # R8 = lpCaption
        
        # Text "Success!"
        "   sub rsp, 0x10;"
        "   mov rcx, rsp;"
        "   mov byte ptr [rcx], 0x53;"     # S
        "   mov byte ptr [rcx+1], 0x75;"   # u
        "   mov byte ptr [rcx+2], 0x63;"   # c
        "   mov byte ptr [rcx+3], 0x63;"   # c
        "   mov byte ptr [rcx+4], 0x65;"   # e
        "   mov byte ptr [rcx+5], 0x73;"   # s
        "   mov byte ptr [rcx+6], 0x73;"   # s
        "   mov byte ptr [rcx+7], 0x21;"   # !
        "   mov byte ptr [rcx+8], al;"
        "   mov rdx, rcx;"                 # RDX = lpText
        
        "   xor r9d, r9d;"                 # uType = 0
        "   xor ecx, ecx;"                 # hWnd = NULL
        "   sub rsp, 0x20;"
        "   call r13;"
        
        # ============================================
        # EPILOGUE
        # ============================================
        "epilogue:"
        "   mov rsp, rbp;"
        "   pop r15;"
        "   pop r14;"
        "   pop r13;"
        "   pop r12;"
        "   pop r11;"
        "   pop r10;"
        "   pop r9;"
        "   pop r8;"
        "   pop rbp;"
        "   pop rdi;"
        "   pop rsi;"
        "   pop rdx;"
        "   pop rcx;"
        "   pop rbx;"
        "   pop rax;"
        "   popfq;"
        "   jmp shellcode_end;"
        
        "parse_module:"
        "   mov ecx, dword ptr [r9 + 0x3c];"
        "   xor r15, r15;"
        "   mov r15b, 0x88;"
        "   add r15, r9;"
        "   add r15, rcx;"
        "   mov r15d, dword ptr [r15];"
        "   add r15, r9;"
        "   mov ecx, dword ptr [r15 + 0x18];"
        "   mov r14d, dword ptr [r15 + 0x20];"
        "   add r14, r9;"

        "search_function:"
        "   jrcxz not_found;"
        "   dec ecx;"
        "   xor rsi, rsi;"
        "   mov esi, [r14 + rcx*4];"
        "   add rsi, r9;"

        "function_hashing:"
        "   xor rax, rax;"
        "   xor rdx, rdx;"
        "   cld;"

        "iteration:"
        "   lodsb;"
        "   test al, al;"
        "   jz compare_hash;"
        "   ror edx, 0x0d;"
        "   add edx, eax;"
        "   jmp iteration;"

        "compare_hash:"
        "   cmp edx, r8d;"
        "   jnz search_function;"
        "   mov r10d, [r15 + 0x24];"
        "   add r10, r9;"
        "   movzx ecx, word ptr [r10 + 2*rcx];"
        "   mov r11d, [r15 + 0x1c];"
        "   add r11, r9;"
        "   mov eax, [r11 + 4*rcx];"
        "   add rax, r9;"
        "   ret;"
        
        "not_found:"
        "   xor eax, eax;"
        "   ret;"
        
        "shellcode_end:"
    )
    return CODE


def main():
    import argparse
    parser = argparse.ArgumentParser(description='MessageBox Shellcode Generator')
    parser.add_argument('-s', '--size', type=int, default=0, help='Target size (pad with NOPs)')
    parser.add_argument('-o', '--output', type=str, help='Output binary file')
    parser.add_argument('--no-test', action='store_true', help='Skip execution test')
    args = parser.parse_args()
    
    print("=" * 60)
    print("  Windows x64 MessageBox Shellcode Generator")
    print("  Author: Senzee")
    print("=" * 60)
    
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    try:
        encoding, count = ks.asm(generate_shellcode_asm())
    except Exception as e:
        print(f"[-] Assembly error: {e}")
        return 1
    
    shellcode = bytearray(encoding)
    actual_size = len(shellcode)
    print(f"[+] Assembled: {count} instructions, {actual_size} bytes")
    
    # Handle size padding
    if args.size > 0:
        if actual_size > args.size:
            print(f"[-] ERROR: {actual_size} > {args.size}. Increase size.")
            return 1
        padding = args.size - actual_size
        shellcode.extend(b'\x90' * padding)
        print(f"[+] Padded: +{padding} NOPs = {len(shellcode)} bytes")
    
    # Save to file
    if args.output:
        with open(args.output, 'wb') as f:
            f.write(shellcode)
        print(f"[+] Saved: {args.output}")
    
    # Print shellcode
    print("\n# Python Format")
    for i in range(0, len(shellcode), 20):
        chunk = shellcode[i:i+20]
        hex_str = ''.join(f'\\x{b:02x}' for b in chunk)
        prefix = 'buf =  b"' if i == 0 else 'buf += b"'
        print(f'{prefix}{hex_str}"')
    
    print(f"\n[+] Final size: {len(shellcode)} bytes")
    
    # Test (unless --no-test)
    if not args.no_test:
        print("\n[*] Testing...")
        try:
            ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
            ptr = ctypes.windll.kernel32.VirtualAlloc(
                ctypes.c_int(0),
                ctypes.c_int(len(shellcode)),
                ctypes.c_int(0x3000),
                ctypes.c_int(0x40)
            )
            
            buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(bytes(shellcode))
            ctypes.windll.kernel32.RtlMoveMemory(
                ctypes.c_uint64(ptr),
                buf,
                ctypes.c_int(len(shellcode))
            )
            print(f"[+] Loaded at: {hex(ptr)}")

            ht = ctypes.windll.kernel32.CreateThread(
                ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.c_uint64(ptr),
                ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.pointer(ctypes.c_int(0))
            )

            ctypes.windll.kernel32.WaitForSingleObject(
                ctypes.c_int(ht),
                ctypes.c_int(-1)
            )
            print("[+] Done!")
            
        except AttributeError:
            print("[-] Not Windows, skipping test")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
