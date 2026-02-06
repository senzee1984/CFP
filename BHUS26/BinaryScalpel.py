#!/usr/bin/env python3
"""
PE Byte Inserter v2 - A tool for inserting bytes into PE executables

Methods:
1. New section method - Create a new section and redirect execution via JMP
2. Code cave method - Find existing code caves and use them (uses LARGEST cave)
3. In-place insertion - Insert bytes and fix all references (analysis mode with CFG detection)

Target: x64 vanilla PE files from C/C++ compilers (MSVC, GCC, Clang)
"""

import argparse
import struct
import os
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Dict, Tuple, Optional, Set
from copy import deepcopy

import pefile
import capstone
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

# ============================================================================
# Data Structures
# ============================================================================

class RefType(Enum):
    """Types of references that need fixing after byte insertion"""
    # Code references (in .text)
    REL_CALL = auto()       # E8 xx xx xx xx
    REL_JMP = auto()        # E9 xx xx xx xx  
    REL_JCC = auto()        # 0F 8x xx xx xx xx (conditional jump near)
    REL_SHORT_JMP = auto()  # EB xx
    REL_SHORT_JCC = auto()  # 7x xx (conditional jump short)
    RIP_RELATIVE = auto()   # [rip+disp32] - data access (mov, lea, cmp, etc.)
    
    # Relocation table references
    ABS_RELOC = auto()      # Absolute address in relocation table (VA, needs ImageBase adjustment)
    
    # Exception handling metadata (.pdata / .xdata)
    PDATA_BEGIN = auto()    # .pdata function start (32-bit RVA)
    PDATA_END = auto()      # .pdata function end (32-bit RVA)
    PDATA_UNWIND = auto()   # .pdata unwind info RVA (32-bit RVA)
    UNWIND_HANDLER = auto() # UNWIND_INFO exception/unwind handler RVA (32-bit RVA)
    
    # Export/Import references
    EXPORT_RVA = auto()     # Export table function RVA (32-bit RVA)
    
    # TLS references
    TLS_CALLBACK = auto()   # TLS callback function address (64-bit VA)
    
    # Security features
    SAFESEG_HANDLER = auto() # SafeSEH handler RVA (32-bit, x86 only)
    CFG_FUNCTION = auto()   # CFG valid call target (32-bit RVA)
    CFG_IAT_ENTRY = auto()  # CFG IAT entry
    CFG_LONGJMP = auto()    # CFG longjmp target
    CFG_EHCONT = auto()     # CFG exception handler continuation
    
    # Data section references
    JUMP_TABLE_ENTRY = auto()  # Jump table entry - 32-bit RVA in data section
    FUNC_PTR_RVA = auto()      # Function pointer - 32-bit RVA pointing to function start
    VA_PTR_64 = auto()         # 64-bit VA pointer in data sections (vtables, func ptr arrays)
    
    # Memory operand displacement pointing to .text (non-RIP-relative)
    DISP32_TEXT_PTR = auto()   # disp32 in [base + index*scale + disp32] pointing to .text


@dataclass
class Reference:
    """A reference that may need updating after byte insertion"""
    ref_type: RefType
    location_rva: int       # Where the reference is located
    target_rva: int         # What it points to
    instruction_size: int   # Size of the instruction/entry
    ref_offset: int         # Offset within instruction to the reference value
    ref_size: int           # Size of reference value (1, 4, or 8 bytes)
    
    def __repr__(self):
        return f"Ref({self.ref_type.name}, loc=0x{self.location_rva:X}, target=0x{self.target_rva:X})"


@dataclass
class CodeCave:
    """A region of null/padding bytes that can be used for code injection"""
    rva: int
    size: int
    section_name: str
    file_offset: int
    

@dataclass
class InsertionPoint:
    """Describes where and what to insert"""
    rva: int
    content: bytes


@dataclass
class CFGInfo:
    """Control Flow Guard information"""
    enabled: bool = False
    instrumented: bool = False
    function_table_rva: int = 0
    function_count: int = 0
    iat_entry_table_rva: int = 0
    iat_entry_count: int = 0
    longjmp_table_rva: int = 0
    longjmp_count: int = 0
    ehcont_table_rva: int = 0
    ehcont_count: int = 0
    guard_flags: int = 0


@dataclass
class PEValidation:
    """PE validation results"""
    is_valid: bool = True
    is_64bit: bool = False
    has_text_section: bool = False
    is_likely_vanilla: bool = True
    warnings: List[str] = field(default_factory=list)
    suspicious_sections: List[str] = field(default_factory=list)
    detected_compiler: str = "Unknown"


@dataclass
class ShiftZone:
    """Represents a zone where bytes shift by a specific amount"""
    start_rva: int          # Start of this zone (inclusive)
    end_rva: int            # End of this zone (exclusive) - start of padding that absorbs
    shift_amount: int       # How many bytes to shift in this zone
    absorbing_padding_rva: int  # RVA of padding that absorbs the shift
    absorbing_padding_size: int # Size of that padding


@dataclass
class ImpactAnalysis:
    """Results of analyzing the impact of an insertion"""
    insertion_rva: int
    insertion_size: int
    affected_range_start: int
    affected_range_end: int
    available_padding: int
    needs_section_expansion: bool
    
    # Padding regions found (rva, size)
    padding_regions: List[Tuple[int, int]] = field(default_factory=list)
    trailing_padding: int = 0
    
    # Shift zones for segmented absorption (new!)
    shift_zones: List[ShiftZone] = field(default_factory=list)
    use_segmented_absorption: bool = False
    
    # References that need fixing
    relative_refs: List[Reference] = field(default_factory=list)      # call/jmp/jcc rel32
    rip_relative_refs: List[Reference] = field(default_factory=list)  # [rip+disp32] data access
    absolute_refs: List[Reference] = field(default_factory=list)      # from .reloc table
    metadata_refs: List[Reference] = field(default_factory=list)      # .pdata, exports, TLS
    cfg_refs: List[Reference] = field(default_factory=list)           # CFG tables
    jump_table_refs: List[Reference] = field(default_factory=list)    # Jump table entries (switch)
    
    # Short jumps that need expansion (causes chain reaction)
    short_jumps_needing_expansion: List[Reference] = field(default_factory=list)
    chain_reaction_extra_bytes: int = 0
    
    # CFG info
    cfg_info: Optional[CFGInfo] = None
    
    # Feasibility assessment
    is_feasible: bool = True
    blocking_reasons: List[str] = field(default_factory=list)


# ============================================================================
# Helper Functions
# ============================================================================

def format_addr(rva: int, file_offset: Optional[int]) -> str:
    """Format address as RVA (File Offset)"""
    if file_offset is not None:
        return f"0x{rva:08X} (File: 0x{file_offset:06X})"
    return f"0x{rva:08X}"


def format_addr_short(rva: int, file_offset: Optional[int]) -> str:
    """Format address as RVA (Offset) - shorter version"""
    if file_offset is not None:
        return f"0x{rva:X} (0x{file_offset:X})"
    return f"0x{rva:X}"


# ============================================================================
# PE Validator
# ============================================================================

class PEValidator:
    """Validates PE files for compatibility with this tool"""
    
    # Known sections from different compilers/tools
    STANDARD_SECTIONS = {
        '.text', '.data', '.rdata', '.bss', '.idata', '.edata',
        '.rsrc', '.reloc', '.pdata', '.xdata', '.tls', '.debug',
        'CODE', 'DATA', '.CRT', '.gfids', '.00cfg', '.gehcont'
    }
    
    # Suspicious sections that indicate non-vanilla PE
    SUSPICIOUS_SECTIONS = {
        # Packers/Protectors
        'UPX0', 'UPX1', 'UPX2', '.UPX', 'UPX!',
        '.aspack', '.adata', 'ASPack',
        '.nsp0', '.nsp1', '.nsp2',  # NSPack
        'PELock', 'PECrypt',
        '.themida', '.winlice',
        '.vmp0', '.vmp1', '.vmp2',  # VMProtect
        '.enigma1', '.enigma2',
        'Obsidium',
        '.perplex',
        '.petite',
        '.packed',
        '.RLPack',
        'MPRESS1', 'MPRESS2',
        # Go runtime
        '.symtab', '.gopclntab',
        # Rust
        '.rustc',
        # .NET
        '.cormeta',
        # Delphi
        'CODE', 'DATA', 'BSS', '.idata', '.tls', '.rdata', '.reloc', '.rsrc',  # These are OK individually
        'PACKAGEINFO', 'DVCLAL',  # Delphi specific - suspicious
        # Other
        '_winzip_',
        '.ndata',  # NSIS installer
    }
    
    # Go-specific sections
    GO_SECTIONS = {'.symtab', '.gopclntab', 'runtime.', '.note.go.buildid'}
    
    # Delphi-specific sections
    DELPHI_SECTIONS = {'PACKAGEINFO', 'DVCLAL', '.idata'}
    
    def __init__(self, pe: pefile.PE):
        self.pe = pe
        
    def validate(self) -> PEValidation:
        """Perform comprehensive PE validation"""
        result = PEValidation()
        
        # Check architecture
        if self.pe.FILE_HEADER.Machine == 0x8664:  # AMD64
            result.is_64bit = True
        elif self.pe.FILE_HEADER.Machine == 0x14c:  # i386
            result.is_64bit = False
            result.warnings.append("32-bit PE detected - this tool is optimized for x64")
        else:
            result.is_valid = False
            result.warnings.append(f"Unknown machine type: 0x{self.pe.FILE_HEADER.Machine:X}")
            return result
        
        # Check for .text section
        section_names = set()
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            section_names.add(name)
            
        if '.text' in section_names or 'CODE' in section_names:
            result.has_text_section = True
        else:
            # Check for any executable section
            for section in self.pe.sections:
                if section.Characteristics & 0x20000000:  # EXECUTE
                    result.has_text_section = True
                    name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    result.warnings.append(f"No .text section, using executable section '{name}'")
                    break
        
        if not result.has_text_section:
            result.is_valid = False
            result.warnings.append("No executable section found")
            return result
        
        # Check for suspicious sections
        for name in section_names:
            # Skip standard sections
            if name in self.STANDARD_SECTIONS:
                continue
            # Check exact matches with suspicious patterns
            if name in self.SUSPICIOUS_SECTIONS:
                result.suspicious_sections.append(name)
                result.is_likely_vanilla = False
            else:
                # Check if name starts with suspicious prefix
                for suspicious in self.SUSPICIOUS_SECTIONS:
                    if name.startswith(suspicious) and suspicious not in self.STANDARD_SECTIONS:
                        if name not in result.suspicious_sections:
                            result.suspicious_sections.append(name)
                            result.is_likely_vanilla = False
                        break
        
        # Detect compiler/runtime
        result.detected_compiler = self._detect_compiler(section_names)
        
        # Check for Go
        if section_names & self.GO_SECTIONS:
            result.is_likely_vanilla = False
            result.warnings.append("Go executable detected - complex runtime, patching not recommended")
        
        # Check for .NET
        if hasattr(self.pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
            result.is_likely_vanilla = False
            result.warnings.append(".NET executable detected - managed code, patching not recommended")
        
        # Check for TLS callbacks (might indicate packing)
        if hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):
            tls = self.pe.DIRECTORY_ENTRY_TLS.struct
            if tls.AddressOfCallBacks:
                result.warnings.append("TLS callbacks present - could be anti-debug or unpacking stub")
        
        # Check section characteristics for anomalies
        for section in self.pe.sections:
            chars = section.Characteristics
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            
            # Writable + Executable is suspicious
            if (chars & 0x20000000) and (chars & 0x80000000):  # EXECUTE and WRITE
                result.warnings.append(f"Section '{name}' is both writable and executable (potential packer)")
                result.is_likely_vanilla = False
            
            # Very high entropy might indicate packing (would need to calculate)
            raw_size = section.SizeOfRawData
            virtual_size = section.Misc_VirtualSize
            if raw_size > 0 and virtual_size > raw_size * 10:
                result.warnings.append(f"Section '{name}' has unusual size ratio (VirtualSize >> RawSize)")
        
        return result
    
    def _detect_compiler(self, section_names: Set[str]) -> str:
        """Try to detect the compiler used"""
        # Check for Rich header (MSVC)
        if hasattr(self.pe, 'RICH_HEADER') and self.pe.RICH_HEADER:
            return "MSVC (Rich header present)"
        
        # Check for Go
        if section_names & self.GO_SECTIONS:
            return "Go"
        
        # Check for MinGW/GCC patterns
        if '.CRT' in section_names and '.bss' in section_names:
            return "Likely MinGW/GCC"
        
        # Check for Delphi
        if section_names & self.DELPHI_SECTIONS:
            return "Likely Delphi/C++ Builder"
        
        # MSVC typically has these sections
        if {'.text', '.rdata', '.data', '.pdata'} <= section_names:
            return "Likely MSVC"
        
        return "Unknown (possibly MSVC or MinGW)"


# ============================================================================
# PE Analyzer
# ============================================================================

class PEAnalyzer:
    """Analyzes PE files and collects all references"""
    
    def __init__(self, pe: pefile.PE):
        self.pe = pe
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.cs.detail = True
        self.image_base = pe.OPTIONAL_HEADER.ImageBase
        
        # Cache section info
        self.sections = {}
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            self.sections[name] = {
                'rva': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'raw_offset': section.PointerToRawData,
                'characteristics': section.Characteristics
            }
    
    def get_section_for_rva(self, rva: int) -> Optional[str]:
        """Find which section contains a given RVA"""
        for name, info in self.sections.items():
            if info['rva'] <= rva < info['rva'] + info['virtual_size']:
                return name
        return None
    
    def rva_to_offset(self, rva: int) -> Optional[int]:
        """
        Convert RVA to file offset.
        
        Note: Uses max(SizeOfRawData, VirtualSize) for range check to handle
        sections where VirtualSize > RawSize (not uncommon in some PE files).
        """
        for section in self.pe.sections:
            section_size = max(section.SizeOfRawData, section.Misc_VirtualSize)
            if section.VirtualAddress <= rva < section.VirtualAddress + section_size:
                # But actual file offset can only go up to RawSize
                offset_in_section = rva - section.VirtualAddress
                if offset_in_section < section.SizeOfRawData:
                    return offset_in_section + section.PointerToRawData
                else:
                    # RVA is in virtual-only region (beyond raw data)
                    return None
        return None
    
    def get_text_section(self) -> Optional[Dict]:
        """Get .text section info"""
        for name in ['.text', 'CODE', '.code']:
            if name in self.sections:
                return self.sections[name]
        # Fallback: find first executable section
        for section in self.pe.sections:
            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                return self.sections[name]
        return None
    
    def collect_code_references(self, scan_range: Tuple[int, int] = None) -> List[Reference]:
        """
        Disassemble code sections and collect all jump/call/RIP-relative references.
        
        Uses a gap-jumping approach: when linear disassembly stops,
        skip ahead and try again to handle data/padding gaps in .text.
        
        Args:
            scan_range: Optional (start_rva, end_rva) to limit scanning.
                       If None, scans entire .text section (slow for large files).
        """
        references = []
        text = self.get_text_section()
        if not text:
            return references
        
        text_rva = text['rva']
        text_size = text['virtual_size']
        text_end = text_rva + text_size
        
        # Determine scan range
        if scan_range:
            scan_start, scan_end = scan_range
            # Clamp to text section bounds
            scan_start = max(scan_start, text_rva)
            scan_end = min(scan_end, text_end)
        else:
            scan_start = text_rva
            scan_end = text_end
        
        scan_size = scan_end - scan_start
        if scan_size <= 0:
            return references
        
        # Read code bytes for the scan range
        try:
            code_bytes = self.pe.get_data(scan_start, scan_size)
        except Exception as e:
            print(f"  [WARNING] Failed to read code bytes: {e}")
            return references
        
        # Disassemble with gap jumping
        current_offset = 0
        max_gap_skip = 256  # Don't skip more than 256 bytes at a time
        
        while current_offset < len(code_bytes):
            chunk = code_bytes[current_offset:]
            chunk_rva = scan_start + current_offset
            
            # Track if we made progress
            made_progress = False
            last_insn_end = current_offset
            
            for insn in self.cs.disasm(chunk, chunk_rva):
                made_progress = True
                last_insn_end = (insn.address - scan_start) + insn.size
                
                # Collect references from this instruction
                refs = self._analyze_instruction(insn)
                references.extend(refs)
            
            if made_progress:
                # Continue from where disassembly stopped
                current_offset = last_insn_end
            else:
                # No instructions decoded - skip ahead
                current_offset += 1
            
            # Skip padding bytes quickly
            while current_offset < len(code_bytes) and code_bytes[current_offset] in (0x00, 0xCC):
                current_offset += 1
            
            # If we hit non-padding but disassembly failed, try to find code
            if current_offset < len(code_bytes) and not made_progress:
                # Look for likely function starts (common prologues)
                found_code = False
                search_limit = min(current_offset + max_gap_skip, len(code_bytes))
                
                for probe in range(current_offset, search_limit):
                    byte = code_bytes[probe]
                    # Common x64 function prologue bytes
                    if byte in (0x48, 0x4C, 0x55, 0x56, 0x57, 0x53, 0x41, 0x40) or (0x50 <= byte <= 0x5F):
                        current_offset = probe
                        found_code = True
                        break
                    # Skip padding
                    if byte in (0x00, 0xCC, 0x90):
                        continue
                    # Unknown byte - try next aligned position
                    break
                
                if not found_code:
                    # Jump to next 16-byte aligned position
                    current_offset = ((current_offset + 15) // 16) * 16
        
        return references
    
    def collect_code_references_for_insertion(self, insertion_rva: int, affected_end_rva: int) -> List[Reference]:
        """
        Collect code references that might be affected by an insertion.
        
        We need to find:
        1. References FROM the affected range (their rel32 needs adjustment)
        2. References TO the affected range (from anywhere in .text)
        
        For efficiency, we scan:
        - The affected range itself
        - A buffer around it to catch nearby references
        - For large files, we do a targeted scan rather than full .text
        """
        text = self.get_text_section()
        if not text:
            return []
        
        text_rva = text['rva']
        text_end = text_rva + text['virtual_size']
        
        references = []
        text_size = text['virtual_size']
        
        if text_size > 1024 * 1024:  # > 1MB
            # Large section - scan in chunks, focusing on:
            # 1. The affected range with generous buffer
            # 2. Look for references that TARGET the affected range
            
            # Buffer around affected range (catch nearby jumps/calls)
            buffer_size = 0x10000  # 64KB buffer
            
            # Scan affected area with buffer
            scan_start = max(text_rva, insertion_rva - buffer_size)
            scan_end = min(text_end, affected_end_rva + buffer_size)
            
            local_refs = self.collect_code_references((scan_start, scan_end))
            references.extend(local_refs)
            
            # Track what we've seen to avoid duplicates
            seen_refs = set((r.location_rva, r.target_rva) for r in local_refs)
            
            # Also need to find references FROM outside that point INTO affected range
            # This requires scanning the whole .text, but we can do it in chunks
            # Use overlapping chunks to handle instructions that cross boundaries
            chunk_size = 256 * 1024  # 256KB chunks
            overlap = 16  # Overlap to catch cross-boundary instructions
            current_pos = text_rva
            
            while current_pos < text_end:
                # Determine actual chunk end (with overlap for next chunk)
                chunk_end = min(current_pos + chunk_size, text_end)
                
                # Check for overlap with local scan area
                # We need to handle partial overlaps properly to avoid gaps!
                
                # Determine the actual range to scan for this chunk
                actual_start = current_pos
                actual_end = chunk_end
                
                # Skip portions that overlap with local scan
                if actual_end > scan_start and actual_start < scan_end:
                    # There is some overlap with local scan
                    
                    # Scan the part before local scan (if any)
                    if actual_start < scan_start:
                        # Add overlap at the end to catch cross-boundary instructions
                        before_end = min(scan_start + overlap, actual_end)
                        before_refs = self.collect_code_references((actual_start, before_end))
                        for ref in before_refs:
                            # Keep references that could be affected by the insertion:
                            # - Target is in affected range (target will shift)
                            # - Location is in affected range (instruction will shift)
                            # - For RIP-relative: target could be ANYWHERE >= insertion_rva
                            key = (ref.location_rva, ref.target_rva)
                            if key in seen_refs:
                                continue
                            
                            # RIP-relative can have targets outside .text (e.g., .rdata)
                            # We need to keep them if target >= insertion_rva
                            target_affected = ref.target_rva >= insertion_rva
                            location_affected = ref.location_rva >= insertion_rva
                            
                            if (target_affected or location_affected) and ref.location_rva < scan_start:
                                references.append(ref)
                                seen_refs.add(key)
                    
                    # Scan the part after local scan (if any)
                    if actual_end > scan_end:
                        # Start a bit earlier to catch cross-boundary instructions
                        after_start = max(scan_end - overlap, actual_start)
                        after_refs = self.collect_code_references((after_start, actual_end))
                        for ref in after_refs:
                            key = (ref.location_rva, ref.target_rva)
                            if key in seen_refs:
                                continue
                            
                            target_affected = ref.target_rva >= insertion_rva
                            location_affected = ref.location_rva >= insertion_rva
                            
                            if (target_affected or location_affected) and ref.location_rva >= scan_end:
                                references.append(ref)
                                seen_refs.add(key)
                else:
                    # No overlap with local scan - scan this chunk fully
                    chunk_refs = self.collect_code_references((actual_start, actual_end))
                    for ref in chunk_refs:
                        key = (ref.location_rva, ref.target_rva)
                        if key in seen_refs:
                            continue
                        
                        target_affected = ref.target_rva >= insertion_rva
                        location_affected = ref.location_rva >= insertion_rva
                        
                        if target_affected or location_affected:
                            references.append(ref)
                            seen_refs.add(key)
                
                # Move to next chunk (with overlap to handle cross-boundary instructions)
                current_pos = chunk_end - overlap if chunk_end < text_end else chunk_end
        else:
            # Small section - scan everything
            references = self.collect_code_references()
        
        return references
    
    def _analyze_instruction(self, insn) -> List[Reference]:
        """
        Analyze a single instruction for references.
        Returns a list because one instruction can have both control flow AND RIP-relative.
        """
        refs = []
        mnemonic = insn.mnemonic.lower()
        
        # CALL rel32: E8 xx xx xx xx
        if mnemonic == 'call' and insn.bytes[0] == 0xE8:
            target_rva = insn.address + insn.size + struct.unpack('<i', bytes(insn.bytes[1:5]))[0]
            refs.append(Reference(
                ref_type=RefType.REL_CALL,
                location_rva=insn.address,
                target_rva=target_rva,
                instruction_size=insn.size,
                ref_offset=1,
                ref_size=4
            ))
        
        # JMP rel32: E9 xx xx xx xx
        elif mnemonic == 'jmp' and insn.bytes[0] == 0xE9:
            target_rva = insn.address + insn.size + struct.unpack('<i', bytes(insn.bytes[1:5]))[0]
            refs.append(Reference(
                ref_type=RefType.REL_JMP,
                location_rva=insn.address,
                target_rva=target_rva,
                instruction_size=insn.size,
                ref_offset=1,
                ref_size=4
            ))
        
        # JMP rel8: EB xx
        elif mnemonic == 'jmp' and insn.bytes[0] == 0xEB:
            offset = struct.unpack('<b', bytes([insn.bytes[1]]))[0]
            target_rva = insn.address + insn.size + offset
            refs.append(Reference(
                ref_type=RefType.REL_SHORT_JMP,
                location_rva=insn.address,
                target_rva=target_rva,
                instruction_size=insn.size,
                ref_offset=1,
                ref_size=1
            ))
        
        # Conditional jumps (Jcc)
        elif mnemonic.startswith('j') and mnemonic != 'jmp':
            # Short conditional: 7x xx
            if 0x70 <= insn.bytes[0] <= 0x7F:
                offset = struct.unpack('<b', bytes([insn.bytes[1]]))[0]
                target_rva = insn.address + insn.size + offset
                refs.append(Reference(
                    ref_type=RefType.REL_SHORT_JCC,
                    location_rva=insn.address,
                    target_rva=target_rva,
                    instruction_size=insn.size,
                    ref_offset=1,
                    ref_size=1
                ))
            # Near conditional: 0F 8x xx xx xx xx
            elif insn.bytes[0] == 0x0F and 0x80 <= insn.bytes[1] <= 0x8F:
                target_rva = insn.address + insn.size + struct.unpack('<i', bytes(insn.bytes[2:6]))[0]
                refs.append(Reference(
                    ref_type=RefType.REL_JCC,
                    location_rva=insn.address,
                    target_rva=target_rva,
                    instruction_size=insn.size,
                    ref_offset=2,
                    ref_size=4
                ))
        
        # RIP-relative addressing (x64): [rip + disp32]
        # This covers: mov, lea, cmp, test, add, sub, and, or, xor, etc.
        # Also covers: call [rip+x], jmp [rip+x] (indirect through memory)
        # And SSE/AVX: movdqa, movdqu, movaps, etc.
        if hasattr(insn, 'operands'):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    if op.mem.base == capstone.x86.X86_REG_RIP:
                        # RIP-relative: target = instruction_end + displacement
                        disp = op.mem.disp
                        target_rva = insn.address + insn.size + disp
                        
                        # disp_offset tells us where the disp32 is in the instruction
                        # Note: capstone may report incorrect disp_size for some SSE instructions,
                        # but x64 RIP-relative always uses disp32 (4 bytes)
                        if insn.disp_offset > 0:
                            refs.append(Reference(
                                ref_type=RefType.RIP_RELATIVE,
                                location_rva=insn.address,
                                target_rva=target_rva,
                                instruction_size=insn.size,
                                ref_offset=insn.disp_offset,
                                ref_size=4  # Always disp32 in x64 RIP-relative
                            ))
        
        return refs
    
    def collect_relocation_references(self) -> List[Reference]:
        """Collect all entries from the base relocation table"""
        references = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            return references
        
        for reloc in self.pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in reloc.entries:
                if entry.type == 0:  # IMAGE_REL_BASED_ABSOLUTE (padding)
                    continue
                
                rva = entry.rva
                # Read the value at this location
                offset = self.rva_to_offset(rva)
                if offset is None:
                    continue
                
                if entry.type == 3:  # IMAGE_REL_BASED_HIGHLOW (32-bit)
                    target_va = struct.unpack('<I', self.pe.__data__[offset:offset+4])[0]
                    target_rva = target_va - self.image_base
                    ref_size = 4
                elif entry.type == 10:  # IMAGE_REL_BASED_DIR64 (64-bit)
                    target_va = struct.unpack('<Q', self.pe.__data__[offset:offset+8])[0]
                    target_rva = target_va - self.image_base
                    ref_size = 8
                else:
                    continue
                
                references.append(Reference(
                    ref_type=RefType.ABS_RELOC,
                    location_rva=rva,
                    target_rva=target_rva,
                    instruction_size=ref_size,
                    ref_offset=0,
                    ref_size=ref_size
                ))
        
        return references
    
    def collect_pdata_references(self) -> List[Reference]:
        """Collect exception directory entries (.pdata) - x64 only"""
        references = []
        
        # Check for exception directory
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXCEPTION'):
            return references
        
        # .pdata entries: RUNTIME_FUNCTION structures
        exception_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]  # Exception directory
        if exception_dir.VirtualAddress == 0:
            return references
        
        pdata_rva = exception_dir.VirtualAddress
        pdata_size = exception_dir.Size
        pdata_offset = self.rva_to_offset(pdata_rva)
        
        if pdata_offset is None:
            return references
        
        # Each RUNTIME_FUNCTION is 12 bytes: BeginAddress(4), EndAddress(4), UnwindData(4)
        entry_size = 12
        num_entries = pdata_size // entry_size
        
        for i in range(num_entries):
            entry_rva = pdata_rva + i * entry_size
            entry_offset = pdata_offset + i * entry_size
            
            begin_addr = struct.unpack('<I', self.pe.__data__[entry_offset:entry_offset+4])[0]
            end_addr = struct.unpack('<I', self.pe.__data__[entry_offset+4:entry_offset+8])[0]
            unwind_info = struct.unpack('<I', self.pe.__data__[entry_offset+8:entry_offset+12])[0]
            
            if begin_addr:
                references.append(Reference(
                    ref_type=RefType.PDATA_BEGIN,
                    location_rva=entry_rva,
                    target_rva=begin_addr,
                    instruction_size=4,
                    ref_offset=0,
                    ref_size=4
                ))
            
            if end_addr:
                references.append(Reference(
                    ref_type=RefType.PDATA_END,
                    location_rva=entry_rva + 4,
                    target_rva=end_addr,
                    instruction_size=4,
                    ref_offset=0,
                    ref_size=4
                ))
            
            if unwind_info:
                references.append(Reference(
                    ref_type=RefType.PDATA_UNWIND,
                    location_rva=entry_rva + 8,
                    target_rva=unwind_info,
                    instruction_size=4,
                    ref_offset=0,
                    ref_size=4
                ))
        
        return references
    
    def collect_unwind_handler_references(self) -> List[Reference]:
        """
        Collect exception handler RVAs from UNWIND_INFO structures.
        
        x64 UNWIND_INFO structure:
        - Byte 0: Version:3 | Flags:5
        - Byte 1: SizeOfProlog
        - Byte 2: CountOfCodes
        - Byte 3: FrameRegister:4 | FrameOffset:4
        - UNWIND_CODE array (2 bytes each, DWORD-aligned)
        - If UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER:
          - DWORD ExceptionHandler RVA
          - Language-specific handler data
        - If UNW_FLAG_CHAININFO:
          - RUNTIME_FUNCTION chained entry
        """
        references = []
        
        UNW_FLAG_EHANDLER = 0x1
        UNW_FLAG_UHANDLER = 0x2
        UNW_FLAG_CHAININFO = 0x4
        
        # We need to scan all UNWIND_INFO structures referenced by .pdata
        exception_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if exception_dir.VirtualAddress == 0:
            return references
        
        pdata_rva = exception_dir.VirtualAddress
        pdata_size = exception_dir.Size
        pdata_offset = self.rva_to_offset(pdata_rva)
        
        if pdata_offset is None:
            return references
        
        # Track processed UNWIND_INFO RVAs to avoid duplicates
        # (multiple functions can share the same UNWIND_INFO)
        processed_unwind_info = set()
        
        entry_size = 12
        num_entries = pdata_size // entry_size
        
        for i in range(num_entries):
            entry_offset = pdata_offset + i * entry_size
            
            # Read UnwindInfo RVA (third DWORD in RUNTIME_FUNCTION)
            unwind_rva = struct.unpack('<I', self.pe.__data__[entry_offset+8:entry_offset+12])[0]
            
            if unwind_rva in processed_unwind_info:
                continue
            processed_unwind_info.add(unwind_rva)
            
            unwind_offset = self.rva_to_offset(unwind_rva)
            if unwind_offset is None or unwind_offset + 4 > len(self.pe.__data__):
                continue
            
            # Parse UNWIND_INFO header
            version_flags = self.pe.__data__[unwind_offset]
            flags = (version_flags >> 3) & 0x1F
            count_of_codes = self.pe.__data__[unwind_offset + 2]
            
            # Check if this UNWIND_INFO has a handler
            if not (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)):
                continue
            
            # Calculate handler RVA location
            # UNWIND_CODE array is DWORD-aligned
            codes_size = count_of_codes * 2
            if codes_size % 4 != 0:
                codes_size += 2  # Align to DWORD
            
            handler_offset = unwind_offset + 4 + codes_size
            if handler_offset + 4 > len(self.pe.__data__):
                continue
            
            handler_rva = struct.unpack('<I', self.pe.__data__[handler_offset:handler_offset+4])[0]
            
            # Calculate the RVA of the handler field itself
            handler_field_rva = unwind_rva + 4 + codes_size
            
            references.append(Reference(
                ref_type=RefType.UNWIND_HANDLER,
                location_rva=handler_field_rva,
                target_rva=handler_rva,
                instruction_size=4,
                ref_offset=0,
                ref_size=4
            ))
        
        return references
    
    def collect_export_references(self) -> List[Reference]:
        """Collect export table function RVAs"""
        references = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return references
        
        export_dir = self.pe.DIRECTORY_ENTRY_EXPORT
        
        # Get the RVA of the AddressOfFunctions array
        func_table_rva = export_dir.struct.AddressOfFunctions
        
        for i, exp in enumerate(export_dir.symbols):
            if exp.address:
                # Location of this RVA in the export table
                entry_rva = func_table_rva + i * 4
                references.append(Reference(
                    ref_type=RefType.EXPORT_RVA,
                    location_rva=entry_rva,
                    target_rva=exp.address,
                    instruction_size=4,
                    ref_offset=0,
                    ref_size=4
                ))
        
        return references
    
    def collect_tls_references(self) -> List[Reference]:
        """Collect TLS callback addresses"""
        references = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):
            return references
        
        tls = self.pe.DIRECTORY_ENTRY_TLS.struct
        
        # TLS callbacks are stored as an array of VAs
        callbacks_va = tls.AddressOfCallBacks
        if callbacks_va == 0:
            return references
        
        callbacks_rva = callbacks_va - self.image_base
        callbacks_offset = self.rva_to_offset(callbacks_rva)
        if callbacks_offset is None:
            return references
        
        # Read callback pointers until we hit a null
        idx = 0
        while True:
            cb_va = struct.unpack('<Q', self.pe.__data__[callbacks_offset + idx*8:callbacks_offset + idx*8 + 8])[0]
            if cb_va == 0:
                break
            
            cb_rva = cb_va - self.image_base
            references.append(Reference(
                ref_type=RefType.TLS_CALLBACK,
                location_rva=callbacks_rva + idx * 8,
                target_rva=cb_rva,
                instruction_size=8,
                ref_offset=0,
                ref_size=8
            ))
            idx += 1
        
        return references
    
    def collect_jump_table_references(self) -> List[Reference]:
        """
        Collect jump table entries from data sections.
        
        Jump tables are generated by compilers for switch statements. They contain
        arrays of RVAs pointing to code in .text section. These are NOT in .reloc
        because they're relative to image base, not absolute VAs.
        
        Detection strategy (two-pronged approach for robustness):
        
        1. DISASSEMBLY-BASED (high precision):
           Scan .text for memory access patterns like:
             mov reg32, [base + index*4 + disp32]
           where disp32 points to a data section. This identifies exact jump table locations.
        
        2. HEURISTIC SCAN (catches edge cases):
           Scan data sections for consecutive DWORDs pointing to .text.
           This catches jump tables that might be accessed in unusual ways.
        
        Both methods are combined, with duplicates removed.
        """
        references = []
        
        # Get .text section bounds
        text = self.get_text_section()
        if not text:
            return references
        
        text_start = text['rva']
        text_end = text_start + text['virtual_size']
        text_offset = text['raw_offset']
        text_size = text['raw_size']
        text_data = self.pe.__data__[text_offset:text_offset + text_size]
        
        # Get data sections (potential jump table locations)
        data_sections = []
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            # Exclude code, exception info, relocations, and resources
            if name not in ['.text', '.pdata', '.reloc', '.rsrc', '.xdata']:
                data_sections.append({
                    'name': name,
                    'start': section.VirtualAddress,
                    'end': section.VirtualAddress + section.Misc_VirtualSize,
                    'offset': section.PointerToRawData,
                    'size': section.SizeOfRawData
                })
        
        if not data_sections:
            return references
        
        # =====================================================================
        # Method 1: Disassembly-based detection
        # =====================================================================
        # Look for: mov reg32, [base + index*4 + disp32]
        # where disp32 points to a data section
        
        jump_table_rvas = set()
        
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        
        # Use chunked disassembly with gap-jumping for large .text sections
        offset = 0
        while offset < len(text_data):
            chunk_size = min(0x10000, len(text_data) - offset)  # 64KB chunks
            chunk = text_data[offset:offset + chunk_size]
            chunk_base = text_start + offset
            
            try:
                for insn in cs.disasm(chunk, chunk_base):
                    for op in insn.operands:
                        if op.type == capstone.x86.X86_OP_MEM:
                            # Skip RIP-relative (already handled separately)
                            if op.mem.base == capstone.x86.X86_REG_RIP:
                                continue
                            
                            # Check for scale=4 (DWORD array access)
                            # This is the hallmark of jump table access
                            if op.mem.index != 0 and op.mem.scale == 4:
                                disp = op.mem.disp
                                if disp > 0:  # Positive displacement
                                    # Check if disp points to a data section
                                    for ds in data_sections:
                                        if ds['start'] <= disp < ds['end']:
                                            jump_table_rvas.add(disp)
                                            break
                    
                    # Update offset
                    next_off = (insn.address - text_start) + insn.size
                    if next_off > offset:
                        offset = next_off
            except Exception:
                pass
            
            # If we didn't advance, skip a byte (gap-jumping)
            if offset < (chunk_base - text_start) + chunk_size:
                offset = (chunk_base - text_start) + chunk_size
        
        # =====================================================================
        # Method 2: Heuristic scan of data sections
        # =====================================================================
        # Look for consecutive DWORDs all pointing to .text
        # This catches jump tables that might be accessed differently
        
        MIN_CONSECUTIVE_ENTRIES = 4  # At least 4 entries to be considered a jump table
        
        # IMPORTANT: Exclude UNWIND_INFO regions to avoid double-counting
        # UNWIND_HANDLER references. UNWIND_INFO structures contain RVAs
        # that might look like jump table entries but are actually exception
        # handler addresses already handled by collect_unwind_handler_references.
        unwind_info_regions = self._get_unwind_info_regions()
        
        # Also exclude CFG function table to avoid double-counting with CFG references
        cfg_info = self.collect_cfg_info()
        cfg_start_rva = cfg_info.function_table_rva if cfg_info.function_table_rva else 0
        # CFG entry size depends on guard flags
        cfg_entry_size = 4
        if cfg_info.guard_flags and (cfg_info.guard_flags & 0x10000000):
            cfg_entry_size += (cfg_info.guard_flags >> 28) & 0xF
        cfg_end_rva = cfg_start_rva + (cfg_info.function_count * cfg_entry_size if cfg_info.function_count else 0)
        
        for ds in data_sections:
            ds_offset = ds['offset']
            ds_size = ds['size']
            ds_rva = ds['start']
            
            if ds_offset + ds_size > len(self.pe.__data__):
                ds_size = len(self.pe.__data__) - ds_offset
            
            if ds_size < MIN_CONSECUTIVE_ENTRIES * 4:
                continue
            
            data = self.pe.__data__[ds_offset:ds_offset + ds_size]
            
            i = 0
            while i <= len(data) - MIN_CONSECUTIVE_ENTRIES * 4:
                # Skip if this position is within an UNWIND_INFO region
                current_rva = ds_rva + i
                in_unwind_info = False
                for ui_start, ui_end in unwind_info_regions:
                    if ui_start <= current_rva < ui_end:
                        in_unwind_info = True
                        # Skip to end of this UNWIND_INFO
                        i = ui_end - ds_rva
                        break
                
                if in_unwind_info:
                    continue
                
                # Skip if this position is within CFG function table
                if cfg_start_rva <= current_rva < cfg_end_rva:
                    i = cfg_end_rva - ds_rva
                    continue
                
                # Count consecutive DWORDs pointing to .text
                consecutive = 0
                j = i
                while j + 4 <= len(data):
                    val = struct.unpack('<I', data[j:j+4])[0]
                    if text_start <= val < text_end:
                        consecutive += 1
                        j += 4
                    else:
                        break
                
                if consecutive >= MIN_CONSECUTIVE_ENTRIES:
                    jt_rva = ds_rva + i
                    # Verify this isn't already a known relocation target
                    # (relocations are for VA, not RVA, so jump tables won't be there)
                    jump_table_rvas.add(jt_rva)
                    i = j  # Skip past this jump table
                else:
                    i += 4  # Move to next DWORD boundary
        
        # =====================================================================
        # Convert jump table RVAs to individual entry references
        # =====================================================================
        # IMPORTANT: Track processed entry RVAs to avoid duplicates!
        # This can happen when one jump table is a subset of another,
        # or when overlapping jump tables are detected.
        processed_entry_rvas = set()
        
        # Build set of UNWIND_INFO positions for quick lookup
        unwind_positions = set()
        for ui_start, ui_end in unwind_info_regions:
            for r in range(ui_start, ui_end, 4):
                unwind_positions.add(r)
        
        for jt_rva in sorted(jump_table_rvas):
            jt_offset = self.rva_to_offset(jt_rva)
            if jt_offset is None:
                continue
            
            # Read all entries in this jump table
            entry_idx = 0
            while True:
                entry_offset = jt_offset + entry_idx * 4
                if entry_offset + 4 > len(self.pe.__data__):
                    break
                
                entry_val = struct.unpack('<I', self.pe.__data__[entry_offset:entry_offset+4])[0]
                
                # Stop when we hit a value that's not in .text
                if not (text_start <= entry_val < text_end):
                    break
                
                entry_rva = jt_rva + entry_idx * 4
                
                # Skip if this entry was already processed (from an overlapping jump table)
                if entry_rva in processed_entry_rvas:
                    entry_idx += 1
                    continue
                
                # Skip if this entry is in UNWIND_INFO (handled by collect_unwind_handler_references)
                if entry_rva in unwind_positions:
                    entry_idx += 1
                    continue
                
                processed_entry_rvas.add(entry_rva)
                
                references.append(Reference(
                    ref_type=RefType.JUMP_TABLE_ENTRY,
                    location_rva=entry_rva,
                    target_rva=entry_val,
                    instruction_size=4,
                    ref_offset=0,
                    ref_size=4
                ))
                
                entry_idx += 1
        
        # =====================================================================
        # Method 3: Inline jump tables in .text section
        # =====================================================================
        # Some compilers embed jump tables directly in .text (not .rdata).
        # These are detected by: mov/movsxd reg, [base + index*4 + disp32]
        # where disp32 is within .text range.
        # 
        # The table entries are SIGNED offsets that get added to a base address.
        # These need updating when code shifts.
        
        inline_jt_refs = self._collect_inline_text_jump_tables(
            text_start, text_end, text_offset, text_data, processed_entry_rvas
        )
        references.extend(inline_jt_refs)
        
        return references
    
    def _collect_inline_text_jump_tables(self, text_start: int, text_end: int,
                                          text_offset: int, text_data: bytes,
                                          processed_entry_rvas: Set[int]) -> List[Reference]:
        """
        Collect jump table entries embedded directly in .text section.
        
        Some compilers (especially older MSVC) embed switch statement jump tables
        directly in the code section. Pattern:
            lea  rdx, [rip - X]       ; Get base address (usually 0)
            mov  ecx, [rdx + rax*4 + DISP]  ; Read jump table entry
            add  rcx, rdx             ; Calculate target
            jmp  rcx                  ; Jump to target
        
        The DISP points to an array of DWORDs in .text that are absolute addresses
        (since base is 0) or relative offsets (added to base).
        
        Returns:
            List of Reference objects for inline jump table entries.
        """
        references = []
        
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        
        # Find all inline jump tables using recursive disassembly
        # This handles cases where jump tables are embedded in function bodies
        # and linear disassembly cannot reach code after the data.
        inline_jt_rvas = set()
        
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        
        # For each function, do recursive disassembly following all jump targets
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXCEPTION'):
            for entry in self.pe.DIRECTORY_ENTRY_EXCEPTION:
                func_start = entry.struct.BeginAddress
                func_end = entry.struct.EndAddress
                
                if func_start < text_start or func_end > text_end:
                    continue
                
                # Recursive disassembly: track all addresses to visit
                to_visit = {func_start}
                visited = set()
                
                while to_visit:
                    addr = to_visit.pop()
                    
                    if addr in visited:
                        continue
                    if addr < func_start or addr >= func_end:
                        continue
                    
                    visited.add(addr)
                    
                    offset = addr - text_start
                    if offset < 0 or offset >= len(text_data):
                        continue
                    
                    code = text_data[offset:offset + (func_end - addr)]
                    
                    try:
                        for insn in cs.disasm(code, addr):
                            # Stop if we reach an already-visited address
                            if insn.address != addr and insn.address in visited:
                                break
                            visited.add(insn.address)
                            
                            # Check for scale=4 memory access (jump table)
                            if insn.mnemonic in ['mov', 'movsxd']:
                                for op in insn.operands:
                                    if op.type == capstone.CS_OP_MEM:
                                        mem = op.mem
                                        if mem.scale == 4 and mem.index != 0:
                                            disp = mem.disp
                                            if disp < 0:
                                                disp = disp & 0xFFFFFFFF
                                            if text_start <= disp < text_end:
                                                inline_jt_rvas.add(disp)
                            
                            # Track conditional jump targets
                            if insn.mnemonic.startswith('j') and insn.mnemonic not in ['jmp']:
                                for op in insn.operands:
                                    if op.type == capstone.CS_OP_IMM:
                                        target = op.imm
                                        if func_start <= target < func_end:
                                            to_visit.add(target)
                            
                            # Track unconditional jump targets
                            if insn.mnemonic == 'jmp':
                                for op in insn.operands:
                                    if op.type == capstone.CS_OP_IMM:
                                        target = op.imm
                                        if func_start <= target < func_end:
                                            to_visit.add(target)
                                # Stop linear disassembly after unconditional jump
                                break
                            
                            # Stop at ret
                            if insn.mnemonic in ['ret', 'retn', 'retf']:
                                break
                    except:
                        pass
        
        if not inline_jt_rvas:
            return references
        
        # For each inline jump table, extract entries
        for jt_rva in sorted(inline_jt_rvas):
            jt_offset = jt_rva - text_start
            if jt_offset < 0 or jt_offset >= len(text_data):
                continue
            
            # Estimate table size by reading consecutive entries
            # that look like valid .text addresses
            entry_idx = 0
            max_entries = 64  # Reasonable limit for switch statements
            
            while entry_idx < max_entries:
                entry_file_offset = jt_offset + entry_idx * 4
                if entry_file_offset + 4 > len(text_data):
                    break
                
                entry_val = struct.unpack('<I', text_data[entry_file_offset:entry_file_offset+4])[0]
                
                # Check if entry looks like a .text address
                if not (text_start <= entry_val < text_end):
                    break
                
                entry_rva = jt_rva + entry_idx * 4
                
                # Skip if already processed
                if entry_rva in processed_entry_rvas:
                    entry_idx += 1
                    continue
                
                processed_entry_rvas.add(entry_rva)
                
                references.append(Reference(
                    ref_type=RefType.JUMP_TABLE_ENTRY,
                    location_rva=entry_rva,
                    target_rva=entry_val,
                    instruction_size=4,
                    ref_offset=0,
                    ref_size=4
                ))
                
                entry_idx += 1
        
        return references
    
    def _get_unwind_info_regions(self) -> List[Tuple[int, int]]:
        """
        Get the RVA ranges of all UNWIND_INFO structures.
        
        This is used to exclude UNWIND_INFO regions from jump table detection,
        since UNWIND_INFO structures contain RVAs (like exception handler addresses)
        that might look like jump table entries but should NOT be treated as such.
        
        Returns:
            List of (start_rva, end_rva) tuples for each UNWIND_INFO structure.
        """
        regions = []
        
        # Get .pdata directory
        if not hasattr(self.pe, 'OPTIONAL_HEADER'):
            return regions
        
        exception_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if exception_dir.VirtualAddress == 0:
            return regions
        
        pdata_rva = exception_dir.VirtualAddress
        pdata_size = exception_dir.Size
        pdata_offset = self.rva_to_offset(pdata_rva)
        
        if pdata_offset is None:
            return regions
        
        entry_size = 12
        num_entries = pdata_size // entry_size
        
        seen_unwind_rvas = set()
        
        for i in range(num_entries):
            entry_offset = pdata_offset + i * entry_size
            if entry_offset + 12 > len(self.pe.__data__):
                break
            
            unwind_rva = struct.unpack('<I', self.pe.__data__[entry_offset+8:entry_offset+12])[0]
            
            # Skip if we've already processed this UNWIND_INFO
            if unwind_rva in seen_unwind_rvas:
                continue
            seen_unwind_rvas.add(unwind_rva)
            
            unwind_offset = self.rva_to_offset(unwind_rva)
            if unwind_offset is None or unwind_offset + 4 > len(self.pe.__data__):
                continue
            
            # Parse UNWIND_INFO to determine its size
            version_flags = self.pe.__data__[unwind_offset]
            count_of_codes = self.pe.__data__[unwind_offset + 2]
            flags = (version_flags >> 3) & 0x1F
            
            # Base size: 4 bytes header + unwind codes
            codes_size = count_of_codes * 2
            if codes_size % 4 != 0:
                codes_size += 2  # Align to DWORD
            
            unwind_size = 4 + codes_size
            
            # If there's an exception handler, add handler RVA + optional handler data
            UNW_FLAG_EHANDLER = 0x1
            UNW_FLAG_UHANDLER = 0x2
            UNW_FLAG_CHAININFO = 0x4
            
            if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
                unwind_size += 4  # Exception handler RVA
                # Handler data can vary in size, add a conservative estimate
                unwind_size += 4  # At least the FuncInfo RVA
            elif flags & UNW_FLAG_CHAININFO:
                unwind_size += 12  # Chained RUNTIME_FUNCTION
            
            regions.append((unwind_rva, unwind_rva + unwind_size))
        
        return regions
    
    def collect_function_pointer_references(self) -> List[Reference]:
        """
        Collect function pointer references in data sections.
        
        This detects 32-bit RVA values in .rdata that point to known function
        start addresses (recorded in .pdata). These are typically:
        - C++ vtable entries
        - Function pointer arrays
        - Callback registrations
        
        This approach is much safer than scanning for all .text RVAs because:
        1. Function start addresses are definitively known from .pdata
        2. Random data rarely coincidentally equals a function start address
        3. Strings like "[%d]" won't match function starts
        
        Returns:
            List of Reference objects for function pointer entries.
        """
        references = []
        
        # Get .text section bounds
        text = self.get_text_section()
        if not text:
            return references
        
        text_start = text['rva']
        text_end = text_start + text['virtual_size']
        
        # Build set of known function start addresses from .pdata
        function_starts = self._get_function_start_addresses()
        if not function_starts:
            return references
        
        # Get data sections to scan
        data_sections = []
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            # Scan .rdata where vtables and function pointers typically reside
            if name in ['.rdata', '.data']:
                data_sections.append({
                    'name': name,
                    'start': section.VirtualAddress,
                    'end': section.VirtualAddress + section.Misc_VirtualSize,
                    'offset': section.PointerToRawData,
                    'size': section.SizeOfRawData
                })
        
        if not data_sections:
            return references
        
        # Get regions to exclude (already handled by other methods)
        # 1. UNWIND_INFO regions (handled by collect_unwind_handler_references)
        unwind_regions = set()
        for start, end in self._get_unwind_info_regions():
            for r in range(start, end, 4):
                unwind_regions.add(r)
        
        # 2. Jump table regions (handled by collect_jump_table_references)
        # We'll track these during iteration
        
        # 3. .pdata itself
        exception_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        pdata_start = exception_dir.VirtualAddress
        pdata_end = pdata_start + exception_dir.Size
        
        # 4. CFG function table (handled by collect_cfg_references)
        cfg_regions = set()
        cfg_info = self.collect_cfg_info()
        if cfg_info.function_table_rva and cfg_info.function_count:
            cfg_start = cfg_info.function_table_rva
            # CFG entry size depends on guard flags
            cfg_entry_size = 4
            if cfg_info.guard_flags and (cfg_info.guard_flags & 0x10000000):
                cfg_entry_size += (cfg_info.guard_flags >> 28) & 0xF
            cfg_end = cfg_start + cfg_info.function_count * cfg_entry_size
            for r in range(cfg_start, cfg_end, 4):
                cfg_regions.add(r)
        
        # Track already-added locations to avoid duplicates
        processed_locations = set()
        
        # Scan data sections
        for ds in data_sections:
            ds_offset = ds['offset']
            ds_size = ds['size']
            ds_rva = ds['start']
            
            if ds_offset + ds_size > len(self.pe.__data__):
                ds_size = len(self.pe.__data__) - ds_offset
            
            data = self.pe.__data__[ds_offset:ds_offset + ds_size]
            
            # Scan every DWORD-aligned position
            for i in range(0, len(data) - 4, 4):
                ptr_rva = ds_rva + i
                
                # Skip if in .pdata
                if pdata_start <= ptr_rva < pdata_end:
                    continue
                
                # Skip if in UNWIND_INFO
                if ptr_rva in unwind_regions:
                    continue
                
                # Skip if in CFG function table (handled separately)
                if ptr_rva in cfg_regions:
                    continue
                
                # Skip if already processed
                if ptr_rva in processed_locations:
                    continue
                
                val = struct.unpack('<I', data[i:i+4])[0]
                
                # Check if this value is a known function start address
                if val in function_starts:
                    processed_locations.add(ptr_rva)
                    references.append(Reference(
                        ref_type=RefType.JUMP_TABLE_ENTRY,  # Reuse type for consistency
                        location_rva=ptr_rva,
                        target_rva=val,
                        instruction_size=4,
                        ref_offset=0,
                        ref_size=4
                    ))
        
        return references
    
    def _get_function_start_addresses(self) -> Set[int]:
        """
        Get set of all function start addresses from .pdata.
        
        Returns:
            Set of RVAs that are known function entry points.
        """
        function_starts = set()
        
        # Get .pdata directory
        if not hasattr(self.pe, 'OPTIONAL_HEADER'):
            return function_starts
        
        exception_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if exception_dir.VirtualAddress == 0:
            return function_starts
        
        pdata_rva = exception_dir.VirtualAddress
        pdata_size = exception_dir.Size
        pdata_offset = self.rva_to_offset(pdata_rva)
        
        if pdata_offset is None:
            return function_starts
        
        entry_size = 12
        num_entries = pdata_size // entry_size
        
        for i in range(num_entries):
            entry_offset = pdata_offset + i * entry_size
            if entry_offset + 4 > len(self.pe.__data__):
                break
            
            begin_addr = struct.unpack('<I', self.pe.__data__[entry_offset:entry_offset+4])[0]
            function_starts.add(begin_addr)
        
        return function_starts
    
    def collect_va_pointer_references(self) -> List[Reference]:
        """
        Collect 64-bit VA (Virtual Address) pointer references in data sections.
        
        This is critical for executables WITHOUT .reloc section (RELOCS_STRIPPED),
        which have hardcoded absolute addresses that need updating when code moves.
        
        These VA pointers are typically:
        - C++ vtable entries (virtual function pointers)
        - Global function pointer arrays
        - CRT initialization function tables (__xc_a, __xi_a, etc.)
        - Static callback registrations
        - Exception handler addresses (may point to function interior)
        
        Detection strategy (for RELOCS_STRIPPED executables):
        1. High confidence: VA points to known function start (from .pdata)
        2. Medium confidence: VA points inside a known function (using .pdata begin/end)
        3. Low confidence (not used): Random VA in .text range
        
        Returns:
            List of Reference objects for 64-bit VA pointers.
        """
        references = []
        
        # Check if we need to handle VA pointers manually
        # If .reloc exists and is populated, the Windows loader will handle these
        reloc_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]  # BaseReloc
        has_relocs = reloc_dir.VirtualAddress != 0 and reloc_dir.Size > 8
        
        # Also check if RELOCS_STRIPPED is set
        relocs_stripped = bool(self.pe.FILE_HEADER.Characteristics & 0x1)
        
        if has_relocs and not relocs_stripped:
            # .reloc table exists and is valid, loader will handle VA fixups
            return references
        
        # Get .text section bounds (as VA)
        text = self.get_text_section()
        if not text:
            return references
        
        image_base = self.image_base
        text_start_va = image_base + text['rva']
        text_end_va = image_base + text['rva'] + text['virtual_size']
        
        # Build function information for validation
        function_start_vas = set()
        function_ranges = []  # List of (start_va, end_va) tuples
        
        for rva in self._get_function_start_addresses():
            function_start_vas.add(image_base + rva)
        
        # Also build function ranges from .pdata
        function_ranges = self._get_function_ranges_va()
        
        if not function_start_vas and not function_ranges:
            # No .pdata means we can't validate, too risky to guess
            return references
        
        # Get data sections to scan
        data_sections = []
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            # Scan .rdata where vtables and function pointers typically reside
            # Also scan .data for global function pointers
            if name in ['.rdata', '.data']:
                data_sections.append({
                    'name': name,
                    'start': section.VirtualAddress,
                    'end': section.VirtualAddress + section.Misc_VirtualSize,
                    'offset': section.PointerToRawData,
                    'size': section.SizeOfRawData
                })
        
        if not data_sections:
            return references
        
        # Track processed locations to avoid duplicates
        processed_locations = set()
        
        # Scan data sections for 64-bit VA pointers
        for ds in data_sections:
            ds_offset = ds['offset']
            ds_size = ds['size']
            ds_rva = ds['start']
            
            if ds_offset + ds_size > len(self.pe.__data__):
                ds_size = len(self.pe.__data__) - ds_offset
            
            data = self.pe.__data__[ds_offset:ds_offset + ds_size]
            
            # Scan every QWORD-aligned position
            for i in range(0, len(data) - 8, 8):
                ptr_rva = ds_rva + i
                
                # Skip if already processed
                if ptr_rva in processed_locations:
                    continue
                
                val = struct.unpack('<Q', data[i:i+8])[0]
                
                # Check if this value looks like a VA pointing to .text
                if text_start_va <= val < text_end_va:
                    # Convert to RVA for storage
                    target_rva = val - image_base
                    
                    # Check 1: High confidence - exact function start
                    if val in function_start_vas:
                        processed_locations.add(ptr_rva)
                        references.append(Reference(
                            ref_type=RefType.VA_PTR_64,
                            location_rva=ptr_rva,
                            target_rva=target_rva,
                            instruction_size=8,
                            ref_offset=0,
                            ref_size=8
                        ))
                        continue
                    
                    # Check 2: Medium confidence - inside or near a known function
                    # This catches pointers to exception handlers, alternate entry points, etc.
                    # We extend the range because:
                    # 1. .pdata addresses are sometimes imprecise
                    # 2. Code may exist in small gaps between functions
                    # 3. Thunks/trampolines may exist before function starts
                    # 4. Epilogue code may be just past the recorded end
                    # 5. Some small functions may not be in .pdata at all
                    TOLERANCE_BEFORE = 128  # Allow up to 128 bytes before function start
                    TOLERANCE_AFTER = 128   # Allow up to 128 bytes after function end
                    for func_start_va, func_end_va in function_ranges:
                        if (func_start_va - TOLERANCE_BEFORE) <= val <= (func_end_va + TOLERANCE_AFTER):
                            processed_locations.add(ptr_rva)
                            references.append(Reference(
                                ref_type=RefType.VA_PTR_64,
                                location_rva=ptr_rva,
                                target_rva=target_rva,
                                instruction_size=8,
                                ref_offset=0,
                                ref_size=8
                            ))
                            break
        
        return references
    
    def _get_function_ranges_va(self) -> List[Tuple[int, int]]:
        """
        Get list of (start_va, end_va) tuples for all functions from .pdata.
        
        Returns:
            List of (start_va, end_va) tuples.
        """
        ranges = []
        
        if not hasattr(self.pe, 'OPTIONAL_HEADER'):
            return ranges
        
        exception_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if exception_dir.VirtualAddress == 0:
            return ranges
        
        pdata_rva = exception_dir.VirtualAddress
        pdata_size = exception_dir.Size
        pdata_offset = self.rva_to_offset(pdata_rva)
        
        if pdata_offset is None:
            return ranges
        
        image_base = self.image_base
        entry_size = 12
        num_entries = pdata_size // entry_size
        
        for i in range(num_entries):
            entry_offset = pdata_offset + i * entry_size
            if entry_offset + 8 > len(self.pe.__data__):
                break
            
            begin_rva = struct.unpack('<I', self.pe.__data__[entry_offset:entry_offset+4])[0]
            end_rva = struct.unpack('<I', self.pe.__data__[entry_offset+4:entry_offset+8])[0]
            
            ranges.append((image_base + begin_rva, image_base + end_rva))
        
        return ranges
    
    def collect_scattered_rva_references(self) -> List[Reference]:
        """
        [REPLACED] Now calls collect_function_pointer_references().
        
        The old implementation was too aggressive and corrupted data.
        The new implementation only detects RVAs that point to known
        function start addresses (from .pdata), which is much safer.
        """
        return self.collect_function_pointer_references()
    
    def collect_disp32_text_references(self) -> List[Reference]:
        """
        Collect memory operand displacement values that point to .text section.
        
        This handles instructions like:
            mov ecx, [rsi + rax*4 + 0xC388]
        where 0xC388 is an address within .text (typically an inline jump table).
        
        When code shifts, if the displacement target is within the shifted region,
        the displacement value itself must be updated.
        
        NOTE: This function ONLY collects DISP32_TEXT_PTR references for the
        displacement values in the instructions. The actual jump table entries
        are collected separately by _collect_inline_text_jump_tables() to avoid
        double-counting.
        
        Note: RIP-relative addressing is handled separately by RIP_RELATIVE refs.
        This only handles non-RIP base registers with absolute-ish displacements.
        
        Uses gap-jumping disassembly to handle data embedded in .text section.
        
        Returns:
            List of Reference objects for disp32 values pointing to .text.
        """
        references = []
        
        text = self.get_text_section()
        if not text:
            return references
        
        text_start = text['rva']
        text_end = text_start + text['virtual_size']
        text_offset = text['raw_offset']
        text_size = text['raw_size']
        
        try:
            text_data = self.pe.__data__[text_offset:text_offset + text_size]
        except:
            return references
        
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        
        # Track processed to avoid duplicates
        processed_insns = set()
        
        # Use gap-jumping disassembly (similar to collect_code_references)
        current_offset = 0
        max_gap_skip = 256
        
        while current_offset < len(text_data):
            chunk = text_data[current_offset:]
            chunk_rva = text_start + current_offset
            
            made_progress = False
            last_insn_end = current_offset
            
            try:
                for insn in cs.disasm(chunk, chunk_rva):
                    made_progress = True
                    last_insn_end = (insn.address - text_start) + insn.size
                    
                    # Check memory operands
                    for op in insn.operands:
                        if op.type == capstone.x86.X86_OP_MEM:
                            # Skip RIP-relative (handled by RIP_RELATIVE refs)
                            if op.mem.base == capstone.x86.X86_REG_RIP:
                                continue
                            
                            disp = op.mem.disp
                            # Convert negative to unsigned for comparison
                            if disp < 0:
                                disp_unsigned = disp & 0xFFFFFFFF
                            else:
                                disp_unsigned = disp
                            
                            # Check if displacement points to .text
                            if text_start <= disp_unsigned < text_end:
                                disp_offset = self._find_disp32_offset_in_instruction(insn, disp)
                                
                                if disp_offset is not None and insn.address not in processed_insns:
                                    processed_insns.add(insn.address)
                                    references.append(Reference(
                                        ref_type=RefType.DISP32_TEXT_PTR,
                                        location_rva=insn.address,
                                        target_rva=disp_unsigned,
                                        instruction_size=insn.size,
                                        ref_offset=disp_offset,
                                        ref_size=4
                                    ))
                                    # NOTE: We do NOT collect jump table entries here anymore.
                                    # That is handled by _collect_inline_text_jump_tables() to avoid
                                    # double-updating the same entries.
            except:
                pass
            
            if made_progress:
                current_offset = last_insn_end
            else:
                current_offset += 1
            
            # Skip padding bytes quickly
            while current_offset < len(text_data) and text_data[current_offset] in (0x00, 0xCC):
                current_offset += 1
            
            # If we hit non-padding but disassembly failed, try to find code
            if current_offset < len(text_data) and not made_progress:
                found_code = False
                search_limit = min(current_offset + max_gap_skip, len(text_data))
                
                for probe in range(current_offset, search_limit):
                    byte = text_data[probe]
                    # Common x64 function prologue bytes
                    if byte in (0x48, 0x4C, 0x55, 0x56, 0x57, 0x53, 0x41, 0x40) or (0x50 <= byte <= 0x5F):
                        current_offset = probe
                        found_code = True
                        break
                    if byte in (0x00, 0xCC, 0x90):
                        continue
                    break
                
                if not found_code:
                    current_offset = ((current_offset + 15) // 16) * 16
        
        return references
    
    def _find_disp32_offset_in_instruction(self, insn, target_disp: int) -> Optional[int]:
        """
        Find the byte offset of a disp32 value within an instruction.
        
        Args:
            insn: Capstone instruction object
            target_disp: The displacement value we're looking for
            
        Returns:
            Offset within instruction bytes, or None if not found.
        """
        insn_bytes = bytes(insn.bytes)
        
        # Convert target_disp to 4-byte little-endian
        if target_disp < 0:
            target_bytes = struct.pack('<i', target_disp)
        else:
            target_bytes = struct.pack('<I', target_disp & 0xFFFFFFFF)
        
        # Search for this pattern in instruction bytes
        # Start searching from offset 1 (skip opcode byte at minimum)
        for i in range(1, len(insn_bytes) - 3):
            if insn_bytes[i:i+4] == target_bytes:
                return i
        
        # Try signed version if unsigned didn't match
        if target_disp >= 0:
            target_bytes_signed = struct.pack('<i', target_disp)
            for i in range(1, len(insn_bytes) - 3):
                if insn_bytes[i:i+4] == target_bytes_signed:
                    return i
        
        return None
    
    def collect_cfg_info(self) -> CFGInfo:
        """Collect Control Flow Guard information"""
        cfg = CFGInfo()
        
        # Check DllCharacteristics for CFG flag
        if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000:  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
            cfg.enabled = True
        
        # Check Load Config Directory
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            return cfg
        
        lc = self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        
        # Check GuardFlags
        if hasattr(lc, 'GuardFlags'):
            cfg.guard_flags = lc.GuardFlags
            if cfg.guard_flags & 0x100:  # IMAGE_GUARD_CF_INSTRUMENTED
                cfg.instrumented = True
        
        # GuardCFFunctionTable
        if hasattr(lc, 'GuardCFFunctionTable') and lc.GuardCFFunctionTable:
            cfg.function_table_rva = lc.GuardCFFunctionTable - self.image_base
            if hasattr(lc, 'GuardCFFunctionCount'):
                cfg.function_count = lc.GuardCFFunctionCount
        
        # GuardAddressTakenIatEntryTable
        if hasattr(lc, 'GuardAddressTakenIatEntryTable') and lc.GuardAddressTakenIatEntryTable:
            cfg.iat_entry_table_rva = lc.GuardAddressTakenIatEntryTable - self.image_base
            if hasattr(lc, 'GuardAddressTakenIatEntryCount'):
                cfg.iat_entry_count = lc.GuardAddressTakenIatEntryCount
        
        # GuardLongJumpTargetTable
        if hasattr(lc, 'GuardLongJumpTargetTable') and lc.GuardLongJumpTargetTable:
            cfg.longjmp_table_rva = lc.GuardLongJumpTargetTable - self.image_base
            if hasattr(lc, 'GuardLongJumpTargetCount'):
                cfg.longjmp_count = lc.GuardLongJumpTargetCount
        
        # GuardEHContinuationTable (Windows 10+)
        if hasattr(lc, 'GuardEHContinuationTable') and lc.GuardEHContinuationTable:
            cfg.ehcont_table_rva = lc.GuardEHContinuationTable - self.image_base
            if hasattr(lc, 'GuardEHContinuationCount'):
                cfg.ehcont_count = lc.GuardEHContinuationCount
        
        return cfg
    
    def collect_cfg_references(self) -> Tuple[List[Reference], CFGInfo]:
        """Collect CFG table entries that would need updating"""
        references = []
        cfg_info = self.collect_cfg_info()
        
        if not cfg_info.enabled and not cfg_info.instrumented:
            return references, cfg_info
        
        # Helper to read CFG table entries
        def read_cfg_table(table_rva: int, count: int, ref_type: RefType) -> List[Reference]:
            refs = []
            if table_rva == 0 or count == 0:
                return refs
            
            table_offset = self.rva_to_offset(table_rva)
            if table_offset is None:
                return refs
            
            # Entry size: 4 bytes RVA + optional metadata
            # Check GuardFlags for metadata size
            entry_size = 4
            if cfg_info.guard_flags & 0x10000000:  # Has extra metadata
                extra = (cfg_info.guard_flags >> 28) & 0xF
                entry_size += extra
            
            for i in range(count):
                entry_rva = table_rva + i * entry_size
                entry_offset = table_offset + i * entry_size
                
                if entry_offset + 4 > len(self.pe.__data__):
                    break
                
                func_rva = struct.unpack('<I', self.pe.__data__[entry_offset:entry_offset+4])[0]
                
                refs.append(Reference(
                    ref_type=ref_type,
                    location_rva=entry_rva,
                    target_rva=func_rva,
                    instruction_size=entry_size,
                    ref_offset=0,
                    ref_size=4
                ))
            
            return refs
        
        # Collect from each CFG table
        references.extend(read_cfg_table(
            cfg_info.function_table_rva, 
            cfg_info.function_count, 
            RefType.CFG_FUNCTION
        ))
        
        references.extend(read_cfg_table(
            cfg_info.iat_entry_table_rva,
            cfg_info.iat_entry_count,
            RefType.CFG_IAT_ENTRY
        ))
        
        references.extend(read_cfg_table(
            cfg_info.longjmp_table_rva,
            cfg_info.longjmp_count,
            RefType.CFG_LONGJMP
        ))
        
        references.extend(read_cfg_table(
            cfg_info.ehcont_table_rva,
            cfg_info.ehcont_count,
            RefType.CFG_EHCONT
        ))
        
        return references, cfg_info
    
    def collect_all_references(self) -> Dict[str, List[Reference]]:
        """Collect all types of references"""
        cfg_refs, _ = self.collect_cfg_references()
        return {
            'code': self.collect_code_references(),
            'relocations': self.collect_relocation_references(),
            'pdata': self.collect_pdata_references(),
            'unwind_handlers': self.collect_unwind_handler_references(),
            'exports': self.collect_export_references(),
            'tls': self.collect_tls_references(),
            'cfg': cfg_refs
        }
    
    def find_code_caves(self, min_size: int = 16, section_filter: str = None) -> List[CodeCave]:
        """Find code caves (regions of padding bytes) in sections
        
        Args:
            min_size: Minimum cave size in bytes
            section_filter: If specified, only search in this section (e.g., '.text')
        """
        caves = []
        
        def is_padding(byte):
            return byte in (0x00, 0xCC)  # null or int3
        
        for section in self.pe.sections:
            # Check if section is executable or readable
            chars = section.Characteristics
            if not (chars & 0x20000000 or chars & 0x40000000):  # EXECUTE or READ
                continue
            
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            
            # Apply section filter if specified
            if section_filter is not None:
                # Normalize both for comparison (handle with/without dot)
                filter_normalized = section_filter.lower().lstrip('.')
                name_normalized = name.lower().lstrip('.')
                if filter_normalized != name_normalized:
                    continue
            
            section_rva = section.VirtualAddress
            section_data = section.get_data()
            
            # Scan for consecutive padding bytes
            cave_start = None
            for i, byte in enumerate(section_data):
                if is_padding(byte):
                    if cave_start is None:
                        cave_start = i
                else:
                    if cave_start is not None:
                        cave_size = i - cave_start
                        if cave_size >= min_size:
                            caves.append(CodeCave(
                                rva=section_rva + cave_start,
                                size=cave_size,
                                section_name=name,
                                file_offset=section.PointerToRawData + cave_start
                            ))
                        cave_start = None
            
            # Check for cave at end of section
            if cave_start is not None:
                cave_size = len(section_data) - cave_start
                if cave_size >= min_size:
                    caves.append(CodeCave(
                        rva=section_rva + cave_start,
                        size=cave_size,
                        section_name=name,
                        file_offset=section.PointerToRawData + cave_start
                    ))
        
        # Sort by size (largest first)
        return sorted(caves, key=lambda c: c.size, reverse=True)
    
    def find_padding_at_rva(self, rva: int) -> int:
        """Find how many padding bytes follow a given RVA"""
        text = self.get_text_section()
        if not text:
            return 0
        
        text_end = text['rva'] + text['virtual_size']
        if rva >= text_end:
            return 0
        
        offset = self.rva_to_offset(rva)
        if offset is None:
            return 0
        
        def is_padding(byte):
            return byte in (0x00, 0xCC)
        
        count = 0
        max_scan = min(text_end - rva, 0x1000)
        data = self.pe.__data__
        
        for i in range(max_scan):
            if offset + i >= len(data):
                break
            if not is_padding(data[offset + i]):
                break
            count += 1
        
        return count


# ============================================================================
# Impact Analyzer (Method 3)
# ============================================================================

class ImpactAnalyzer:
    """Analyzes the impact of inserting bytes at a specific location"""
    
    def __init__(self, pe_analyzer: PEAnalyzer):
        self.analyzer = pe_analyzer
        self.pe = pe_analyzer.pe
    
    def _check_instruction_boundary(self, insertion_rva: int) -> dict:
        """
        Check if the insertion point is at an instruction boundary.
        
        Returns:
            dict with:
                - is_boundary: True if at instruction boundary
                - crossing_instruction: dict with instruction info if not at boundary
        """
        # Entry point is always a valid instruction boundary by definition
        entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if insertion_rva == entry_point:
            return {'is_boundary': True}
        
        text = self.analyzer.get_text_section()
        if not text:
            return {'is_boundary': True}  # Can't check, assume OK
        
        # Disassemble a region around the insertion point
        # Start from a safe distance before (to catch long instructions)
        scan_start = max(text['rva'], insertion_rva - 32)
        scan_size = min(64, text['rva'] + text['virtual_size'] - scan_start)
        
        try:
            code_bytes = self.pe.get_data(scan_start, scan_size)
        except:
            return {'is_boundary': True}  # Can't read, assume OK
        
        # Disassemble and find instruction boundaries
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        for insn in md.disasm(code_bytes, scan_start):
            insn_start = insn.address
            insn_end = insn.address + insn.size - 1  # Last byte of instruction
            
            # Check if insertion point falls inside this instruction (not at start)
            if insn_start < insertion_rva <= insn_end:
                return {
                    'is_boundary': False,
                    'crossing_instruction': {
                        'start': insn_start,
                        'end': insn_end,
                        'size': insn.size,
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str
                    }
                }
            
            # If we've passed the insertion point, we're at a boundary
            if insn_start >= insertion_rva:
                return {'is_boundary': True}
        
        # If disassembly didn't reach insertion point, check if it's in padding
        return {'is_boundary': True}
    
    def _is_padding_byte(self, byte: int) -> bool:
        """Check if a byte is potentially padding (basic check, used for trailing padding)"""
        return byte in (0x00, 0xCC)
    
    def _find_safe_padding_regions(self, section_data: bytes, start_offset: int, text_start_rva: int,
                                      excluded_regions: List[Tuple[int, int]] = None) -> List[Tuple[int, int]]:
        """
        Find padding regions using multiple safety checks:
        1. Must be at instruction boundary (disassembly-verified)
        2. Preferably after terminating instructions (ret, jmp, int3)
        3. 0xCC (INT3) is always safe at any length
        4. 0x00 requires at least 4 consecutive bytes
        5. Must NOT overlap with excluded regions (e.g., jump tables)
        
        This prevents mistaking instruction operands (like 00 00 in call rel32) as padding,
        and also prevents misidentifying jump table data as padding.
        
        Args:
            section_data: Raw bytes of the section
            start_offset: Offset within section_data to start scanning
            text_start_rva: RVA of .text section start
            excluded_regions: List of (rva, size) tuples for regions to exclude (e.g., jump tables)
        
        Returns:
            List of (rva, size) tuples for verified safe padding regions
        """
        safe_padding_regions = []
        
        # Build a set of RVAs that are in excluded regions for fast lookup
        excluded_rvas = set()
        if excluded_regions:
            for ex_rva, ex_size in excluded_regions:
                for r in range(ex_rva, ex_rva + ex_size):
                    excluded_rvas.add(r)
        
        # Step 1: Disassemble to find instruction boundaries and terminators
        code_to_scan = section_data[start_offset:]
        base_rva = text_start_rva + start_offset
        
        # Track instruction boundaries and terminating instructions
        instruction_ends = set()  # Offsets (relative to start_offset) where instructions end
        terminator_ends = set()   # Offsets after ret/jmp/int3
        
        # Terminating instruction patterns
        TERMINATORS = {
            'ret', 'retn', 'retf', 'retfq',  # return instructions
            'jmp',                             # unconditional jump (function tail calls)
            'int3',                            # breakpoint/padding
            'ud2',                             # undefined instruction (unreachable)
            'hlt',                             # halt (unreachable in user code)
        }
        
        # Limit disassembly to reasonable size to avoid performance issues
        # We only need to scan until we find enough padding anyway
        MAX_SCAN_SIZE = min(len(code_to_scan), 1024 * 1024)  # 1MB max
        code_to_disasm = code_to_scan[:MAX_SCAN_SIZE]
        
        try:
            for insn in self.analyzer.cs.disasm(code_to_disasm, base_rva):
                rel_offset = insn.address - base_rva
                insn_end_offset = rel_offset + insn.size
                instruction_ends.add(insn_end_offset)
                
                # Check if this is a terminating instruction
                mnemonic = insn.mnemonic.lower()
                if mnemonic in TERMINATORS:
                    terminator_ends.add(insn_end_offset)
        except Exception as e:
            # If disassembly fails, fall back to conservative approach
            print(f"  [DEBUG] Disassembly failed: {e}")
            pass
        
        # Step 2: Scan for padding regions, but only accept them if they're safe
        i = 0
        scan_limit = min(len(code_to_scan), MAX_SCAN_SIZE)
        
        while i < scan_limit:
            byte = code_to_scan[i]
            
            # Skip non-padding bytes
            if byte not in (0x00, 0xCC):
                i += 1
                continue
            
            # Found a potential padding byte - collect the region
            padding_start = i
            padding_bytes = []
            
            while i < scan_limit and code_to_scan[i] in (0x00, 0xCC):
                padding_bytes.append(code_to_scan[i])
                i += 1
            
            padding_size = len(padding_bytes)
            padding_rva = base_rva + padding_start
            
            # Step 3: Apply safety checks
            is_safe = False
            reject_reason = ""
            
            # Check 1: Is this at an instruction boundary?
            at_instruction_boundary = padding_start in instruction_ends
            
            # Check 2: Is this after a terminating instruction?
            after_terminator = padding_start in terminator_ends
            
            # Check 3: Is it all 0xCC (INT3)?
            all_int3 = all(b == 0xCC for b in padding_bytes)
            
            # Check 4: Is it at least 4 consecutive 0x00?
            min_null_length = 4
            enough_nulls = (padding_size >= min_null_length) and (0x00 in padding_bytes)
            
            # Safety decision:
            # CRITICAL FIX: Even multiple INT3 bytes can appear in instruction operands!
            # For example: movabs rax, 0xCCCCCCCCCCCCCCCD contains 7 consecutive 0xCC bytes
            # This constant is used by MSVC for fast division by 10.
            # 
            # Analysis: movabs has an 8-byte immediate operand. The worst case is
            # 0xCCCCCCCCCCCCCCCC which would have 8 consecutive 0xCC. But constants like
            # 0xCCCCCCCCCCCCCCCD have only 7 consecutive 0xCC (the CD breaks the sequence).
            # 
            # RULE: >= 8 consecutive 0xCC is always safe (no instruction operand is that long)
            # For shorter sequences, we use additional heuristics.
            
            MIN_SAFE_CC_ALWAYS = 8  # No instruction operand has 8+ consecutive 0xCC
            
            if all_int3 and padding_size >= MIN_SAFE_CC_ALWAYS:
                # 8+ consecutive INT3 bytes - always safe padding
                is_safe = True
            elif all_int3 and padding_size >= 2:
                # 2-7 INT3 bytes - could be operand, use heuristics
                # Trust the boundary check if available, but also consider that
                # consecutive int3 padding is very common after ret/jmp
                if at_instruction_boundary or after_terminator:
                    is_safe = True
                else:
                    # Additional heuristic: check if the byte BEFORE this sequence
                    # could be part of a movabs instruction (0x48 0xB8 pattern)
                    # This is expensive so only do it for suspicious cases
                    check_offset = padding_start - 2  # Look for 48 B8 before the CC sequence
                    if check_offset >= 0:
                        # Check if this looks like it could be inside a movabs
                        prev_bytes = code_to_scan[check_offset:padding_start]
                        if len(prev_bytes) >= 2 and prev_bytes[-2:] == bytes([0x48, 0xB8]):
                            # Very likely inside a movabs instruction!
                            reject_reason = f"{padding_size} 0xCC bytes after 48 B8 (likely movabs operand)"
                        elif len(prev_bytes) >= 1 and prev_bytes[-1] in [0xCD, 0xCE, 0xCF]:
                            # Previous byte is CDh/CEh/CFh which could be part of 0xCCCCCCCC...CD pattern
                            reject_reason = f"{padding_size} 0xCC bytes after 0x{prev_bytes[-1]:02X} (may be in movabs operand)"
                        else:
                            # Doesn't look like movabs, probably safe
                            is_safe = True
                    else:
                        # At the very beginning, less likely to be in an operand
                        is_safe = True
            elif all_int3 and padding_size == 1:
                # Single 0xCC - must verify it's at instruction boundary
                # because 0xCC can appear in instruction operands (e.g., jmp [rip+0x43CC])
                if at_instruction_boundary:
                    is_safe = True
                else:
                    reject_reason = "single 0xCC not at instruction boundary (may be in operand)"
            elif at_instruction_boundary:
                if after_terminator:
                    # After ret/jmp/int3 - very safe
                    is_safe = True
                elif enough_nulls:
                    # At instruction boundary with enough consecutive nulls
                    is_safe = True
                else:
                    reject_reason = f"at boundary but only {padding_size} nulls (need >= {min_null_length})"
            elif not instruction_ends:
                # Fallback: if disassembly didn't work, use conservative heuristics
                if all_int3:
                    is_safe = True
                elif padding_size >= min_null_length and all(b == 0x00 for b in padding_bytes):
                    is_safe = True
                else:
                    reject_reason = f"no disasm data, only {padding_size} bytes"
            else:
                reject_reason = f"NOT at instruction boundary (inside instruction operand?)"
            
            # Check 5: Is this region in an excluded area (e.g., jump table)?
            if is_safe and excluded_rvas:
                # Check if any byte in this padding region is in an excluded area
                for offset in range(padding_size):
                    if (padding_rva + offset) in excluded_rvas:
                        is_safe = False
                        reject_reason = f"overlaps with excluded region (jump table?) at 0x{padding_rva + offset:X}"
                        break
            
            if is_safe:
                safe_padding_regions.append((padding_rva, padding_size))
        
        return safe_padding_regions
    
    def _find_affected_range_end(self, insertion_rva: int, insertion_size: int) -> Tuple[int, int, List[Tuple[int, int]], List['ShiftZone'], bool]:
        """
        Calculate affected range and decide on optimal strategy.
        
        Strategy selection:
        - If function-internal padding (excluding .text trailing) can absorb ALL inserted bytes:
          → Use segmented absorption (elegant, fewer reference fixes)
        - Otherwise:
          → Use simple whole-shift to .text end (simpler, since we need trailing space anyway)
        
        Returns:
            - affected_end_rva: RVA where affected range ends
            - total_available_padding: total padding bytes available
            - padding_regions: list of (rva, size) tuples
            - shift_zones: list of ShiftZone objects (empty if using simple shift)
            - use_segmented: True if segmented absorption is beneficial
        """
        text = self.analyzer.get_text_section()
        if not text:
            return insertion_rva + insertion_size, 0, [], [], False
        
        text_start = text['rva']
        text_end = text_start + text['virtual_size']
        raw_offset = text['raw_offset']
        raw_size = text['raw_size']
        
        section_data = self.pe.__data__[raw_offset:raw_offset + raw_size]
        insertion_offset = insertion_rva - text_start
        virtual_size = text['virtual_size']
        
        # Collect jump table regions to exclude from padding detection
        # Jump tables contain 0x00 bytes (high bytes of RVAs) that look like padding but aren't
        jump_table_refs = self.analyzer.collect_jump_table_references()
        
        # Build excluded regions from jump tables
        # Group consecutive jump table entries into regions
        excluded_regions = []
        if jump_table_refs:
            # Sort by location
            sorted_refs = sorted(jump_table_refs, key=lambda r: r.location_rva)
            
            # Group consecutive entries (each entry is 4 bytes for 32-bit RVAs)
            current_start = None
            current_end = None
            
            for ref in sorted_refs:
                loc = ref.location_rva
                # Only consider jump tables in .text section (some may be in .rdata)
                if not (text_start <= loc < text_end):
                    continue
                    
                if current_start is None:
                    current_start = loc
                    current_end = loc + 4  # 4 bytes per entry
                elif loc <= current_end:
                    # Consecutive or overlapping
                    current_end = max(current_end, loc + 4)
                else:
                    # Gap - save current region and start new one
                    excluded_regions.append((current_start, current_end - current_start))
                    current_start = loc
                    current_end = loc + 4
            
            # Don't forget the last region
            if current_start is not None:
                excluded_regions.append((current_start, current_end - current_start))
        
        # Use safe padding detection (disassembly-verified, multiple safety checks)
        # Pass excluded_regions to avoid treating jump table data as padding
        padding_regions = self._find_safe_padding_regions(section_data, insertion_offset, text_start, excluded_regions)
        
        # IMPORTANT: Section tail padding (VirtualSize to RawSize) is separate!
        # _find_safe_padding_regions only finds padding within the code (up to VirtualSize).
        # The space between VirtualSize and RawSize is guaranteed to be available
        # and should be added separately as "trailing padding".
        section_tail_padding = raw_size - virtual_size
        if section_tail_padding > 0:
            # The section tail starts at VirtualSize offset and extends to RawSize
            tail_rva = text_start + virtual_size
            # Add it as a separate trailing region
            padding_regions.append((tail_rva, section_tail_padding))
        
        total_padding = sum(p[1] for p in padding_regions)
        
        # Not enough total padding - needs section expansion
        if total_padding < insertion_size:
            return text_end, total_padding, padding_regions, [], False
        
        # Identify trailing padding
        # The trailing padding is the section tail (VirtualSize to RawSize)
        trailing_padding_size = section_tail_padding
        
        # Calculate function-internal padding (excluding trailing)
        # Internal padding = all padding regions except the section tail
        if trailing_padding_size > 0:
            # We appended a trailing region, so internal = all except the last one
            if len(padding_regions) > 1:
                internal_padding = sum(p[1] for p in padding_regions[:-1])
            else:
                internal_padding = 0
        else:
            # No trailing region was appended, ALL regions are internal
            internal_padding = sum(p[1] for p in padding_regions)
        
        # STRATEGY DECISION:
        # If internal padding can absorb everything, use segmented absorption
        # Otherwise, just shift everything to the trailing padding
        use_segmented = (internal_padding >= insertion_size)
        
        if use_segmented:
            # Compute shift zones using only internal padding
            # 
            # KEY INSIGHT: Each zone shifts by the CUMULATIVE amount that will be absorbed
            # by THIS zone's padding and ALL SUBSEQUENT zones' padding.
            #
            # Example: Insert 10 bytes, padding regions of 3, 4, 3 bytes
            #   Zone 1: shifts by 10, absorbs 3 → remaining 7 flows to Zone 2
            #   Zone 2: shifts by 7, absorbs 4 → remaining 3 flows to Zone 3
            #   Zone 3: shifts by 3, absorbs 3 → done
            #
            # First, calculate how much each padding region will absorb
            remaining = insertion_size
            absorptions = []  # (padding_rva, padding_size, absorbed_amount)
            
            # Only use padding regions up to (but not including) the last one (trailing)
            regions_to_use = padding_regions[:-1] if trailing_padding_size > 0 else padding_regions
            
            for padding_rva, padding_size in regions_to_use:
                if remaining <= 0:
                    break
                absorbed = min(padding_size, remaining)
                absorptions.append((padding_rva, padding_size, absorbed))
                remaining -= absorbed
            
            # Now create zones with correct shift amounts
            # Zone N's shift = sum of absorptions from zone N to the last zone
            shift_zones = []
            zone_start_rva = insertion_rva
            
            for i, (padding_rva, padding_size, absorbed) in enumerate(absorptions):
                # This zone's shift is the sum of all remaining absorptions
                zone_shift = sum(a[2] for a in absorptions[i:])
                
                shift_zones.append(ShiftZone(
                    start_rva=zone_start_rva,
                    end_rva=padding_rva,
                    shift_amount=zone_shift,
                    absorbing_padding_rva=padding_rva,
                    absorbing_padding_size=absorbed
                ))
                
                zone_start_rva = padding_rva + padding_size
            
            if shift_zones:
                last_zone = shift_zones[-1]
                affected_end_rva = last_zone.absorbing_padding_rva + last_zone.absorbing_padding_size
            else:
                affected_end_rva = insertion_rva + insertion_size
            
            return affected_end_rva, total_padding, padding_regions, shift_zones, True
        
        else:
            # Simple whole-shift strategy: shift everything to trailing padding
            # Find where actual code ends (before trailing padding)
            actual_code_end = len(section_data)
            for j in range(len(section_data) - 1, insertion_offset - 1, -1):
                if not self._is_padding_byte(section_data[j]):
                    actual_code_end = j + 1
                    break
            
            affected_end_rva = text_start + actual_code_end
            
            # Create a single shift zone for simple shift
            shift_zones = [ShiftZone(
                start_rva=insertion_rva,
                end_rva=affected_end_rva,
                shift_amount=insertion_size,
                absorbing_padding_rva=affected_end_rva,
                absorbing_padding_size=insertion_size
            )]
            
            return affected_end_rva + insertion_size, total_padding, padding_regions, shift_zones, False
    
    def _find_trailing_padding(self, section_rva: int, section_virtual_size: int) -> int:
        """Find how many consecutive padding bytes are at the END of a section."""
        text_section = None
        for section in self.pe.sections:
            if section.VirtualAddress == section_rva:
                text_section = section
                break
        
        if text_section is None:
            return 0
        
        raw_offset = text_section.PointerToRawData
        raw_size = text_section.SizeOfRawData
        
        if raw_offset + raw_size > len(self.pe.__data__):
            raw_size = len(self.pe.__data__) - raw_offset
        
        if raw_size <= 0:
            return 0
        
        data = self.pe.__data__[raw_offset:raw_offset + raw_size]
        
        # Scan backwards from end
        padding_count = 0
        for i in range(len(data) - 1, -1, -1):
            if self._is_padding_byte(data[i]):
                padding_count += 1
            else:
                break
        
        return padding_count
    
    def _find_actual_code_end(self, text_start: int, text_end: int) -> int:
        """Find where actual code ends (before trailing padding)"""
        section_size = text_end - text_start
        padding = self._find_trailing_padding(text_start, section_size)
        return text_end - padding
    
    def analyze(self, insertion_rva: int, insertion_size: int, debug: bool = False) -> ImpactAnalysis:
        """Analyze the full impact of inserting bytes at the given RVA"""
        
        # Get text section bounds
        text = self.analyzer.get_text_section()
        if not text:
            raise ValueError("Cannot find text section")
        
        text_start = text['rva']
        text_end = text['rva'] + text['virtual_size']
        
        if not (text_start <= insertion_rva < text_end):
            raise ValueError(f"Insertion RVA 0x{insertion_rva:X} not in text section")
        
        # Check if insertion point is at an instruction boundary
        boundary_check = self._check_instruction_boundary(insertion_rva)
        if not boundary_check['is_boundary']:
            crossing_insn = boundary_check.get('crossing_instruction')
            if crossing_insn:
                print(f"\n⚠️  WARNING: Insertion point 0x{insertion_rva:X} is in the middle of an instruction!")
                print(f"   Instruction: 0x{crossing_insn['start']:X}-0x{crossing_insn['end']:X}: {crossing_insn['mnemonic']} {crossing_insn['op_str']}")
                print(f"   Suggested insertion points:")
                print(f"     - Before this instruction: 0x{crossing_insn['start']:X}")
                print(f"     - After this instruction:  0x{crossing_insn['end'] + 1:X}")
                raise ValueError(f"Insertion point 0x{insertion_rva:X} is not at an instruction boundary")
        
        # Calculate affected range with strategy selection
        affected_range_end, total_padding, padding_regions, shift_zones, use_segmented = self._find_affected_range_end(
            insertion_rva, insertion_size
        )
        
        trailing_padding = self._find_trailing_padding(text_start, text['virtual_size'])
        needs_expansion = insertion_size > total_padding
        affected_range_start = insertion_rva
        
        # Collect references - use optimized method for code refs
        # This is important for large PE files where full .text disassembly is slow
        code_refs = self.analyzer.collect_code_references_for_insertion(insertion_rva, affected_range_end)
        cfg_refs, cfg_info = self.analyzer.collect_cfg_references()
        
        all_refs = {
            'code': code_refs,
            'relocations': self.analyzer.collect_relocation_references(),
            'pdata': self.analyzer.collect_pdata_references(),
            'unwind_handlers': self.analyzer.collect_unwind_handler_references(),
            'exports': self.analyzer.collect_export_references(),
            'tls': self.analyzer.collect_tls_references(),
            'cfg': cfg_refs,
            'jump_tables': self.analyzer.collect_jump_table_references(),
            'scattered_rvas': self.analyzer.collect_scattered_rva_references(),
            'va_pointers': self.analyzer.collect_va_pointer_references(),
            'disp32_text': self.analyzer.collect_disp32_text_references()
        }
        
        # Debug: show references near insertion point
        if debug:
            print(f"\n[DEBUG] Total code references collected: {len(all_refs['code'])}")
            print(f"[DEBUG] References near insertion point 0x{insertion_rva:X}:")
            nearby_refs = [r for r in all_refs['code'] 
                          if abs(r.location_rva - insertion_rva) < 0x50]
            for ref in nearby_refs[:20]:
                print(f"  {ref.ref_type.name}: loc=0x{ref.location_rva:X} -> target=0x{ref.target_rva:X}")
            if not nearby_refs:
                print(f"  (no code references found near 0x{insertion_rva:X})")
                # Show some references to verify collection is working
                if all_refs['code']:
                    print(f"  First 5 refs collected (to verify): ")
                    for ref in all_refs['code'][:5]:
                        print(f"    {ref.ref_type.name}: loc=0x{ref.location_rva:X} -> target=0x{ref.target_rva:X}")
                    # Also show refs closest to insertion point
                    sorted_refs = sorted(all_refs['code'], key=lambda r: abs(r.location_rva - insertion_rva))
                    print(f"  Closest 5 refs to insertion point:")
                    for ref in sorted_refs[:5]:
                        dist = ref.location_rva - insertion_rva
                        print(f"    {ref.ref_type.name}: loc=0x{ref.location_rva:X} (dist={dist:+d}) -> target=0x{ref.target_rva:X}")
            print(f"\n[DEBUG] Shift zones:")
            for i, zone in enumerate(shift_zones):
                print(f"  Zone {i}: 0x{zone.start_rva:X} - 0x{zone.end_rva:X}, shift={zone.shift_amount}")
        
        # Create analysis result
        analysis = ImpactAnalysis(
            insertion_rva=insertion_rva,
            insertion_size=insertion_size,
            affected_range_start=affected_range_start,
            affected_range_end=affected_range_end,
            available_padding=total_padding,
            needs_section_expansion=needs_expansion,
            padding_regions=padding_regions,
            trailing_padding=trailing_padding,
            shift_zones=shift_zones,
            use_segmented_absorption=use_segmented,
            cfg_info=cfg_info
        )
        
        # Analyze each reference
        # For control flow references (call/jmp/jcc), check if they cross shift zone boundaries
        for ref in all_refs['code']:
            if ref.ref_type == RefType.RIP_RELATIVE:
                # RIP-relative data access - needs fixing if instruction OR target shifts
                # (different from control flow which only cares about relative distance)
                if self._reference_needs_fixing_segmented(ref, shift_zones):
                    analysis.rip_relative_refs.append(ref)
            elif ref.ref_type in (RefType.REL_SHORT_JMP, RefType.REL_SHORT_JCC):
                if self._reference_needs_fixing_segmented(ref, shift_zones):
                    # Check overflow with max possible shift
                    max_shift = shift_zones[0].shift_amount if shift_zones else insertion_size
                    if self._short_jump_will_overflow(ref, insertion_rva, max_shift):
                        analysis.short_jumps_needing_expansion.append(ref)
                        analysis.chain_reaction_extra_bytes += 4
                    else:
                        analysis.relative_refs.append(ref)
            else:
                # REL_CALL, REL_JMP, REL_JCC
                if self._reference_needs_fixing_segmented(ref, shift_zones):
                    analysis.relative_refs.append(ref)
        
        # Collect TLS callback locations to avoid double-fixing
        # TLS callbacks are 64-bit VAs that also appear in .reloc table as ABS_RELOC
        # If we fix them both as TLS_CALLBACK and ABS_RELOC, they get shifted twice!
        tls_callback_locations = set()
        for ref in all_refs['tls']:
            tls_callback_locations.add(ref.location_rva)
        
        # For absolute references, check if target is in any shift zone
        # BUT skip any that are also TLS callbacks (to avoid double-fixing)
        for ref in all_refs['relocations']:
            # Skip if this location is a TLS callback (already handled by metadata fix)
            if ref.location_rva in tls_callback_locations:
                continue
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            if target_shift > 0:
                analysis.absolute_refs.append(ref)
        
        # For metadata references, check if target shifts
        # Special handling for .pdata: End addresses at exactly the insertion point
        # should NOT shift (they mark the end of functions BEFORE the insertion)
        insertion_point = insertion_rva
        for ref in all_refs['pdata']:
            # PDATA_END at exactly insertion point should not shift
            if ref.ref_type == RefType.PDATA_END and ref.target_rva == insertion_point:
                continue  # Skip - this End marks a function that doesn't move
            
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            if target_shift > 0:
                analysis.metadata_refs.append(ref)
        
        # UNWIND_INFO handlers - these point to exception handler code
        for ref in all_refs['unwind_handlers']:
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            if target_shift > 0:
                analysis.metadata_refs.append(ref)
        
        for ref in all_refs['exports']:
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            if target_shift > 0:
                analysis.metadata_refs.append(ref)
        
        for ref in all_refs['tls']:
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            if target_shift > 0:
                analysis.metadata_refs.append(ref)
        
        # Jump table references - switch statement targets in data sections
        # Track locations to avoid duplicates with scattered_rvas
        jump_table_locations = set()
        for ref in all_refs['jump_tables']:
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            if target_shift > 0:
                analysis.jump_table_refs.append(ref)
                jump_table_locations.add(ref.location_rva)
        
        # Scattered RVA references (function pointers, vtables) - also use jump_table_refs
        # IMPORTANT: Skip locations already covered by jump_tables to avoid double-fixing
        for ref in all_refs['scattered_rvas']:
            if ref.location_rva in jump_table_locations:
                continue  # Already handled by jump_tables
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            if target_shift > 0:
                analysis.jump_table_refs.append(ref)
                jump_table_locations.add(ref.location_rva)  # Track to avoid VA pointer duplicates
        
        # 64-bit VA pointer references (vtables, function pointer arrays in RELOCS_STRIPPED executables)
        # IMPORTANT: Skip locations already covered by jump_tables/scattered_rvas
        for ref in all_refs['va_pointers']:
            if ref.location_rva in jump_table_locations:
                continue  # Already handled
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            if target_shift > 0:
                analysis.jump_table_refs.append(ref)
        
        # DISP32_TEXT_PTR references (memory operand displacement pointing to .text)
        # The displacement is an ABSOLUTE address, so it must be updated whenever
        # the target shifts, regardless of whether the instruction also shifts.
        for ref in all_refs['disp32_text']:
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            # Unlike RIP-relative where relative distance matters,
            # absolute displacement must track target movement
            if target_shift > 0:
                analysis.jump_table_refs.append(ref)
        
        # CFG references
        for ref in cfg_refs:
            target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
            if target_shift > 0:
                analysis.cfg_refs.append(ref)
        
        # Assess feasibility
        self._assess_feasibility(analysis)
        
        return analysis
    
    def _reference_needs_fixing(self, ref: Reference, insertion_rva: int, affected_end: int) -> bool:
        """Determine if a relative reference needs fixing"""
        loc = ref.location_rva
        target = ref.target_rva
        
        # A relative reference needs fixing if:
        # 1. It crosses the insertion boundary (one side shifts, other doesn't)
        # 2. Location and target are in different shift zones (shift by different amounts)
        
        if loc < insertion_rva and target >= insertion_rva:
            return True
        
        if loc >= insertion_rva and loc < affected_end:
            if target < insertion_rva:
                return True
            return True
        
        return False
    
    def _reference_needs_fixing_segmented(self, ref: Reference, shift_zones: List[ShiftZone]) -> bool:
        """
        Determine if a relative reference needs fixing using shift zones.
        A reference needs fixing if location and target shift by different amounts.
        """
        if not shift_zones:
            # This should not happen in Method 3 - we always create at least one zone
            # But if it does, CONSERVATIVELY assume fix IS needed (better to over-fix than miss)
            return True
        
        loc_shift = self._get_shift_for_rva_analysis(ref.location_rva, shift_zones)
        target_shift = self._get_shift_for_rva_analysis(ref.target_rva, shift_zones)
        
        return loc_shift != target_shift
    
    def _get_shift_for_rva_analysis(self, rva: int, shift_zones: List[ShiftZone]) -> int:
        """Get shift amount for analysis (same logic as InPlaceInserter._get_shift_for_rva)"""
        if not shift_zones:
            return 0
        
        # CRITICAL: Only .text section addresses shift!
        text_section = self.analyzer.get_text_section()
        if text_section:
            text_start = text_section['rva']
            text_end = text_start + text_section['virtual_size']
            if not (text_start <= rva < text_end):
                return 0
        
        if rva < shift_zones[0].start_rva:
            return 0
        
        for i, zone in enumerate(shift_zones):
            if zone.start_rva <= rva < zone.end_rva:
                return zone.shift_amount
            
            padding_end = zone.absorbing_padding_rva + zone.absorbing_padding_size
            if zone.absorbing_padding_rva <= rva < padding_end:
                return zone.shift_amount
            
            if i + 1 < len(shift_zones):
                next_zone_start = shift_zones[i + 1].start_rva
                if padding_end <= rva < next_zone_start:
                    return shift_zones[i + 1].shift_amount
        
        last_zone = shift_zones[-1]
        last_padding_end = last_zone.absorbing_padding_rva + last_zone.absorbing_padding_size
        if rva >= last_padding_end:
            return 0
        
        return 0
    
    def _reference_target_in_range(self, ref: Reference, start_rva: int, end_rva: int) -> bool:
        """Check if reference target is in the affected range"""
        return start_rva <= ref.target_rva < end_rva
    
    def _short_jump_will_overflow(self, ref: Reference, insertion_rva: int, max_shift: int) -> bool:
        """
        Check if a short jump will overflow after insertion.
        
        Uses CONSERVATIVE approach: assumes maximum possible shift amount.
        For segmented absorption, the actual shift might be smaller, but if
        max_shift doesn't cause overflow, the actual shift definitely won't.
        
        This is intentionally conservative because:
        - Short jump: -128 to +127 range
        - If we underestimate and it overflows at runtime, the binary crashes
        - Better to flag as potential overflow and handle it
        """
        loc = ref.location_rva
        target = ref.target_rva
        insn_end = loc + ref.instruction_size
        
        current_offset = target - insn_end
        
        # Determine if location/target cross the insertion boundary
        loc_moves = loc >= insertion_rva
        target_moves = target >= insertion_rva
        
        if loc_moves and target_moves:
            # Both move - relative distance unchanged
            return False
        elif not loc_moves and not target_moves:
            # Neither moves - no change
            return False
        elif not loc_moves and target_moves:
            # Target moves away - offset increases
            new_offset = current_offset + max_shift
        else:
            # Location moves, target doesn't - offset decreases
            new_offset = current_offset - max_shift
        
        return new_offset < -128 or new_offset > 127
    
    def _assess_feasibility(self, analysis: ImpactAnalysis):
        """Assess whether Method 3 insertion is feasible"""
        analysis.is_feasible = True
        analysis.blocking_reasons = []
        
        # Check 1: Section expansion required
        if analysis.needs_section_expansion:
            analysis.is_feasible = False
            analysis.blocking_reasons.append(
                f"Section expansion required: need {analysis.insertion_size} bytes but only "
                f"{analysis.available_padding} bytes of padding available"
            )
        
        # Check 2: Chain reaction from short jumps
        if analysis.chain_reaction_extra_bytes > 0:
            total_needed = analysis.insertion_size + analysis.chain_reaction_extra_bytes
            if total_needed > analysis.available_padding:
                analysis.is_feasible = False
                analysis.blocking_reasons.append(
                    f"Chain reaction: {len(analysis.short_jumps_needing_expansion)} short jump(s) would overflow, "
                    f"requiring {analysis.chain_reaction_extra_bytes} extra bytes "
                    f"(total {total_needed} > available {analysis.available_padding})"
                )
        
        # Check 3: Verify shift won't overflow into next section
        # This is critical when insertion point is near section end
        if analysis.shift_zones:
            text = self.analyzer.get_text_section()
            if text:
                text_raw_end = text['raw_offset'] + text['raw_size']
                
                for zone in analysis.shift_zones:
                    # Calculate the file offset where shifted data would end up
                    zone_end_offset = self.analyzer.rva_to_offset(zone.end_rva)
                    if zone_end_offset is not None:
                        shifted_end_offset = zone_end_offset + zone.shift_amount
                        
                        if shifted_end_offset > text_raw_end:
                            overflow_bytes = shifted_end_offset - text_raw_end
                            analysis.is_feasible = False
                            analysis.blocking_reasons.append(
                                f"Section overflow: shift would write {overflow_bytes} bytes past .text section end "
                                f"(shifted data ends at file offset 0x{shifted_end_offset:X}, "
                                f".text ends at 0x{text_raw_end:X}). "
                                f"Consider using a smaller insertion size or different insertion point."
                            )
                            break


# ============================================================================
# Method 1: New Section Injection
# ============================================================================

class NewSectionInjector:
    """Inject code by creating a new section"""
    
    def __init__(self, pe: pefile.PE):
        self.pe = pe
        self.analyzer = PEAnalyzer(pe)
    
    def inject(self, hook_rva: int, payload: bytes, section_name: str = ".hook") -> bytes:
        """Create a new section with payload, redirect execution from hook_rva"""
        pe_data = bytearray(self.pe.__data__)
        
        file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        
        last_section = self.pe.sections[-1]
        
        new_section_rva = self._align(
            last_section.VirtualAddress + last_section.Misc_VirtualSize,
            section_alignment
        )
        
        new_section_offset = self._align(
            last_section.PointerToRawData + last_section.SizeOfRawData,
            file_alignment
        )
        
        hook_offset = self.analyzer.rva_to_offset(hook_rva)
        if hook_offset is None:
            raise ValueError(f"Cannot resolve hook RVA 0x{hook_rva:X}")
        
        original_bytes = bytes(pe_data[hook_offset:hook_offset+14])
        
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        instructions = list(cs.disasm(original_bytes, hook_rva))
        
        bytes_to_overwrite = 0
        for insn in instructions:
            bytes_to_overwrite += insn.size
            if bytes_to_overwrite >= 5:
                break
        
        if bytes_to_overwrite < 5:
            raise ValueError("Not enough space for JMP at hook point")
        
        saved_bytes = bytes(pe_data[hook_offset:hook_offset+bytes_to_overwrite])
        
        trampoline = bytearray()
        trampoline.extend(self._relocate_instructions(saved_bytes, hook_rva, new_section_rva))
        trampoline.extend(payload)
        
        jmp_back_target = hook_rva + bytes_to_overwrite
        jmp_back_from = new_section_rva + len(trampoline) + 5
        jmp_back_offset = jmp_back_target - jmp_back_from
        trampoline.extend(b'\xE9')
        trampoline.extend(struct.pack('<i', jmp_back_offset))
        
        trampoline_size = len(trampoline)
        aligned_size = self._align(trampoline_size, file_alignment)
        trampoline.extend(b'\x00' * (aligned_size - trampoline_size))
        
        section_header = self._create_section_header(
            name=section_name,
            virtual_size=len(trampoline),
            virtual_address=new_section_rva,
            raw_size=aligned_size,
            raw_offset=new_section_offset,
            characteristics=0x60000020
        )
        
        section_header_offset = (
            self.pe.DOS_HEADER.e_lfanew + 4 + 20 +
            self.pe.FILE_HEADER.SizeOfOptionalHeader +
            self.pe.FILE_HEADER.NumberOfSections * 40
        )
        
        first_section_offset = self.pe.sections[0].PointerToRawData
        if section_header_offset + 40 > first_section_offset:
            raise ValueError("No space for new section header")
        
        pe_data[section_header_offset:section_header_offset+40] = section_header
        
        num_sections_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 2
        pe_data[num_sections_offset:num_sections_offset+2] = struct.pack('<H', 
            self.pe.FILE_HEADER.NumberOfSections + 1)
        
        new_size_of_image = self._align(new_section_rva + aligned_size, section_alignment)
        size_of_image_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 56
        pe_data[size_of_image_offset:size_of_image_offset+4] = struct.pack('<I', new_size_of_image)
        
        jmp_to_trampoline = hook_rva + 5
        jmp_offset = new_section_rva - jmp_to_trampoline
        pe_data[hook_offset] = 0xE9
        pe_data[hook_offset+1:hook_offset+5] = struct.pack('<i', jmp_offset)
        
        for i in range(5, bytes_to_overwrite):
            pe_data[hook_offset + i] = 0x90
        
        if len(pe_data) < new_section_offset:
            pe_data.extend(b'\x00' * (new_section_offset - len(pe_data)))
        
        pe_data.extend(trampoline)
        
        return bytes(pe_data)
    
    def _align(self, value: int, alignment: int) -> int:
        return (value + alignment - 1) & ~(alignment - 1)
    
    def _create_section_header(self, name: str, virtual_size: int, virtual_address: int,
                               raw_size: int, raw_offset: int, characteristics: int) -> bytes:
        header = bytearray(40)
        name_bytes = name.encode('utf-8')[:8].ljust(8, b'\x00')
        header[0:8] = name_bytes
        header[8:12] = struct.pack('<I', virtual_size)
        header[12:16] = struct.pack('<I', virtual_address)
        header[16:20] = struct.pack('<I', raw_size)
        header[20:24] = struct.pack('<I', raw_offset)
        header[36:40] = struct.pack('<I', characteristics)
        return bytes(header)
    
    def _relocate_instructions(self, code: bytes, old_rva: int, new_rva: int) -> bytes:
        result = bytearray(code)
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        offset = 0
        for insn in cs.disasm(code, old_rva):
            if insn.bytes[0] == 0xE8:
                old_target = old_rva + offset + 5 + struct.unpack('<i', code[offset+1:offset+5])[0]
                new_target_offset = old_target - (new_rva + offset + 5)
                result[offset+1:offset+5] = struct.pack('<i', new_target_offset)
            elif insn.bytes[0] == 0xE9:
                old_target = old_rva + offset + 5 + struct.unpack('<i', code[offset+1:offset+5])[0]
                new_target_offset = old_target - (new_rva + offset + 5)
                result[offset+1:offset+5] = struct.pack('<i', new_target_offset)
            offset += insn.size
        
        return bytes(result)


# ============================================================================
# Method 2: Code Cave Injection
# ============================================================================

class CodeCaveInjector:
    """Inject code using existing code caves"""
    
    def __init__(self, pe: pefile.PE):
        self.pe = pe
        self.analyzer = PEAnalyzer(pe)
    
    def inject(self, hook_rva: int, payload: bytes, cave: Optional[CodeCave] = None) -> bytes:
        """Inject payload into a code cave, redirect from hook_rva"""
        # Find LARGEST suitable cave if not specified
        if cave is None:
            caves = self.analyzer.find_code_caves(min_size=len(payload) + 20)
            if not caves:
                raise ValueError("No suitable code cave found")
            # caves are already sorted by size (largest first)
            cave = caves[0]
        
        if cave.size < len(payload) + 15:
            raise ValueError(f"Code cave too small: {cave.size} bytes")
        
        pe_data = bytearray(self.pe.__data__)
        
        hook_offset = self.analyzer.rva_to_offset(hook_rva)
        if hook_offset is None:
            raise ValueError(f"Cannot resolve hook RVA 0x{hook_rva:X}")
        
        original_bytes = bytes(pe_data[hook_offset:hook_offset+14])
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        bytes_to_overwrite = 0
        for insn in cs.disasm(original_bytes, hook_rva):
            bytes_to_overwrite += insn.size
            if bytes_to_overwrite >= 5:
                break
        
        if bytes_to_overwrite < 5:
            raise ValueError("Not enough space for JMP at hook point")
        
        saved_bytes = bytes(pe_data[hook_offset:hook_offset+bytes_to_overwrite])
        
        trampoline = bytearray()
        trampoline.extend(self._relocate_instructions(saved_bytes, hook_rva, cave.rva))
        trampoline.extend(payload)
        
        jmp_back_target = hook_rva + bytes_to_overwrite
        jmp_back_from = cave.rva + len(trampoline) + 5
        jmp_back_offset = jmp_back_target - jmp_back_from
        trampoline.extend(b'\xE9')
        trampoline.extend(struct.pack('<i', jmp_back_offset))
        
        pe_data[cave.file_offset:cave.file_offset+len(trampoline)] = trampoline
        
        # Make cave section executable if needed
        for section in self.pe.sections:
            if section.VirtualAddress <= cave.rva < section.VirtualAddress + section.Misc_VirtualSize:
                if not (section.Characteristics & 0x20000000):
                    chars_offset = (
                        self.pe.DOS_HEADER.e_lfanew + 4 + 20 +
                        self.pe.FILE_HEADER.SizeOfOptionalHeader +
                        self.pe.sections.index(section) * 40 + 36
                    )
                    new_chars = section.Characteristics | 0x20000000
                    pe_data[chars_offset:chars_offset+4] = struct.pack('<I', new_chars)
                break
        
        jmp_offset = cave.rva - (hook_rva + 5)
        pe_data[hook_offset] = 0xE9
        pe_data[hook_offset+1:hook_offset+5] = struct.pack('<i', jmp_offset)
        
        for i in range(5, bytes_to_overwrite):
            pe_data[hook_offset + i] = 0x90
        
        return bytes(pe_data)
    
    def _relocate_instructions(self, code: bytes, old_rva: int, new_rva: int) -> bytes:
        result = bytearray(code)
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        offset = 0
        for insn in cs.disasm(code, old_rva):
            if insn.bytes[0] == 0xE8:
                old_target = old_rva + offset + 5 + struct.unpack('<i', code[offset+1:offset+5])[0]
                new_target_offset = old_target - (new_rva + offset + 5)
                result[offset+1:offset+5] = struct.pack('<i', new_target_offset)
            elif insn.bytes[0] == 0xE9:
                old_target = old_rva + offset + 5 + struct.unpack('<i', code[offset+1:offset+5])[0]
                new_target_offset = old_target - (new_rva + offset + 5)
                result[offset+1:offset+5] = struct.pack('<i', new_target_offset)
            offset += insn.size
        
        return bytes(result)


# ============================================================================
# Assembly Helper
# ============================================================================

class AssemblyHelper:
    """Helper for assembling and disassembling x64 code"""
    
    def __init__(self):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    
    def assemble(self, code: str, address: int = 0) -> bytes:
        try:
            encoding, _ = self.ks.asm(code, address)
            return bytes(encoding)
        except Exception as e:
            raise ValueError(f"Assembly failed: {e}")
    
    def disassemble(self, code: bytes, address: int = 0) -> List[str]:
        result = []
        for insn in self.cs.disasm(code, address):
            result.append(f"0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
        return result


# ============================================================================
# Method 3: In-Place Byte Inserter (FULL IMPLEMENTATION)
# ============================================================================

class InPlaceInserter:
    """
    Performs actual in-place byte insertion with full reference fixing.
    
    Supports two modes:
    1. Simple mode: All bytes shift by the same amount
    2. Segmented absorption: Different zones shift by different amounts
    
    Segmented absorption minimizes the number of references that need fixing.
    """
    
    def __init__(self, pe: pefile.PE, analyzer: PEAnalyzer):
        self.pe = pe
        self.analyzer = analyzer
        self.image_base = pe.OPTIONAL_HEADER.ImageBase
    
    def insert(self, insertion_rva: int, content: bytes, analysis: ImpactAnalysis) -> bytes:
        """
        Perform in-place byte insertion using segmented absorption.
        """
        if not analysis.is_feasible:
            raise ValueError(f"Insertion not feasible: {'; '.join(analysis.blocking_reasons)}")
        
        insertion_size = len(content)
        if insertion_size != analysis.insertion_size:
            raise ValueError(f"Content size {insertion_size} doesn't match analysis size {analysis.insertion_size}")
        
        pe_data = bytearray(self.pe.__data__)
        text = self.analyzer.get_text_section()
        text_raw_offset = text['raw_offset']
        
        insertion_offset = self.analyzer.rva_to_offset(insertion_rva)
        if insertion_offset is None:
            raise ValueError(f"Cannot resolve insertion RVA 0x{insertion_rva:X}")
        
        # Step 1: Perform byte shifting
        if analysis.shift_zones:
            # Distinguish between true segmented absorption vs single-zone whole-shift
            if analysis.use_segmented_absorption:
                print(f"  Using SEGMENTED ABSORPTION with {len(analysis.shift_zones)} zone(s)")
            else:
                print(f"  Using SIMPLE WHOLE-SHIFT (single zone)")
            self._perform_segmented_shift(pe_data, content, analysis.shift_zones)
        else:
            # Fallback to simple shift (should not happen - we always create zones)
            affected_end_offset = self.analyzer.rva_to_offset(analysis.affected_range_end)
            if affected_end_offset is None:
                affected_end_offset = text_raw_offset + text['raw_size']
            
            bytes_to_shift = affected_end_offset - insertion_offset
            print(f"  Simple shift (fallback): {bytes_to_shift} bytes by {insertion_size}")
            
            shifted_bytes = bytes(pe_data[insertion_offset:affected_end_offset])
            pe_data[insertion_offset:insertion_offset + insertion_size] = content
            pe_data[insertion_offset + insertion_size:insertion_offset + insertion_size + bytes_to_shift] = shifted_bytes
        
        # Step 2: Fix all relative code references (call/jmp/jcc)
        print(f"  Fixing {len(analysis.relative_refs)} relative code references...")
        fixes_applied = 0
        debug_count = [0]  # Use list to allow modification in function
        for ref in analysis.relative_refs:
            if self._fix_relative_reference(pe_data, ref, analysis.shift_zones, debug_count):
                fixes_applied += 1
        print(f"    Applied {fixes_applied} relative reference fixes")
        
        # Step 3: Fix all RIP-relative data references
        print(f"  Fixing {len(analysis.rip_relative_refs)} RIP-relative references...")
        fixes_applied = 0
        for ref in analysis.rip_relative_refs:
            if self._fix_rip_relative_reference(pe_data, ref, analysis.shift_zones):
                fixes_applied += 1
        print(f"    Applied {fixes_applied} RIP-relative reference fixes")
        
        # Step 4: Fix all absolute references (relocations)
        print(f"  Fixing {len(analysis.absolute_refs)} absolute references...")
        fixes_applied = 0
        for ref in analysis.absolute_refs:
            if self._fix_absolute_reference(pe_data, ref, analysis.shift_zones):
                fixes_applied += 1
        print(f"    Applied {fixes_applied} absolute reference fixes")
        
        # Step 5: Fix all metadata references (.pdata, exports, TLS)
        print(f"  Fixing {len(analysis.metadata_refs)} metadata references...")
        fixes_applied = 0
        for ref in analysis.metadata_refs:
            if self._fix_metadata_reference(pe_data, ref, analysis.shift_zones):
                fixes_applied += 1
        print(f"    Applied {fixes_applied} metadata reference fixes")
        
        # Step 6: Fix CFG references
        if analysis.cfg_refs:
            print(f"  Fixing {len(analysis.cfg_refs)} CFG references...")
            fixes_applied = 0
            for ref in analysis.cfg_refs:
                if self._fix_cfg_reference(pe_data, ref, analysis.shift_zones):
                    fixes_applied += 1
            print(f"    Applied {fixes_applied} CFG reference fixes")
        
        # Step 7: Fix jump table references (switch statement targets)
        if analysis.jump_table_refs:
            print(f"  Fixing {len(analysis.jump_table_refs)} jump table references...")
            fixes_applied = 0
            for ref in analysis.jump_table_refs:
                if self._fix_jump_table_reference(pe_data, ref, analysis.shift_zones):
                    fixes_applied += 1
            print(f"    Applied {fixes_applied} jump table reference fixes")
        
        print(f"  ✅ All references fixed!")
        
        # Step 8: Disable CFG if present (moving code invalidates CFG tables)
        # Find and clear GuardFlags to prevent CFG check failures
        self._disable_cfg_if_needed(pe_data)
        
        # Step 9: Update Entry Point if it's in the shifted region
        self._update_entry_point_if_needed(pe_data, analysis.shift_zones, insertion_rva)
        
        # Step 10: Update Data Directories if they point to shifted regions
        self._update_data_directories_if_needed(pe_data, analysis.shift_zones)
        
        # Verification: spot check a few RIP-relative references
        if analysis.rip_relative_refs and len(analysis.rip_relative_refs) > 0:
            print(f"\n  [VERIFY] Spot-checking first 3 RIP-relative fixes...")
            for ref in analysis.rip_relative_refs[:3]:
                loc_shift = self._get_shift_for_rva(ref.location_rva, analysis.shift_zones)
                target_shift = self._get_shift_for_rva(ref.target_rva, analysis.shift_zones)
                
                new_loc = ref.location_rva + loc_shift
                new_insn_end = new_loc + ref.instruction_size
                
                # Read the new disp32
                new_loc_offset = self.analyzer.rva_to_offset(ref.location_rva)
                if new_loc_offset and loc_shift > 0:
                    new_loc_offset += loc_shift
                if new_loc_offset:
                    new_disp = struct.unpack('<i', pe_data[new_loc_offset + ref.ref_offset:new_loc_offset + ref.ref_offset + 4])[0]
                    computed_target = new_insn_end + new_disp
                    expected_target = ref.target_rva + target_shift
                    
                    status = "✓" if computed_target == expected_target else "✗ MISMATCH!"
                    print(f"    loc 0x{ref.location_rva:X} → 0x{new_loc:X}: disp=0x{new_disp:X}, target=0x{computed_target:X} (expected 0x{expected_target:X}) {status}")
        
        return bytes(pe_data)
    
    def _disable_cfg_if_needed(self, pe_data: bytearray):
        """
        Disable CFG (Control Flow Guard) by clearing GuardFlags.
        
        When code is moved by byte insertion, CFG valid target addresses become invalid.
        Windows will trigger FAST_FAIL_GUARD_ICALL_CHECK_FAILURE if CFG is enabled
        but the indirect call targets are not in the valid target table.
        
        Rather than trying to update the CFG tables (which is complex), we simply
        disable CFG by clearing the GuardFlags in the Load Config directory.
        """
        # Find Load Config directory
        load_config_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[10]  # IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
        if load_config_dir.VirtualAddress == 0:
            return
        
        load_config_rva = load_config_dir.VirtualAddress
        load_config_offset = self.analyzer.rva_to_offset(load_config_rva)
        if load_config_offset is None:
            return
        
        # Read the size field (first DWORD)
        size = struct.unpack('<I', pe_data[load_config_offset:load_config_offset+4])[0]
        
        # GuardFlags is at offset 0x58 in 32-bit, 0x90 in 64-bit Load Config
        # For x64, the structure layout puts GuardFlags at offset 0x90
        guard_flags_offset = load_config_offset + 0x90
        
        if guard_flags_offset + 4 > len(pe_data):
            return
        
        if size < 0x94:  # Structure too small to have GuardFlags
            return
        
        current_flags = struct.unpack('<I', pe_data[guard_flags_offset:guard_flags_offset+4])[0]
        
        CF_INSTRUMENTED = 0x100
        IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
        
        if current_flags & CF_INSTRUMENTED:
            # Clear CF_INSTRUMENTED flag
            new_flags = current_flags & ~CF_INSTRUMENTED
            pe_data[guard_flags_offset:guard_flags_offset+4] = struct.pack('<I', new_flags)
            print(f"  [CFG] Cleared CF_INSTRUMENTED flag (0x{current_flags:X} -> 0x{new_flags:X})")
        
        # Also clear DllCharacteristics GUARD_CF flag if set
        dll_chars_offset = self.pe.OPTIONAL_HEADER.get_field_absolute_offset('DllCharacteristics')
        if dll_chars_offset:
            current_dll_chars = struct.unpack('<H', pe_data[dll_chars_offset:dll_chars_offset+2])[0]
            if current_dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF:
                new_dll_chars = current_dll_chars & ~IMAGE_DLLCHARACTERISTICS_GUARD_CF
                pe_data[dll_chars_offset:dll_chars_offset+2] = struct.pack('<H', new_dll_chars)
                print(f"  [CFG] Cleared GUARD_CF in DllCharacteristics (0x{current_dll_chars:X} -> 0x{new_dll_chars:X})")
    
    def _update_entry_point_if_needed(self, pe_data: bytearray, shift_zones: List[ShiftZone], insertion_rva: int = None):
        """
        Update the Entry Point (AddressOfEntryPoint) if it's in a shifted region.
        
        The Entry Point is stored in the PE Optional Header and points to the
        first instruction that executes when the program starts. If this address
        is in the shifted region, it must be updated or the program will crash
        (typically executing NOPs or garbage).
        
        EXCEPTION: If the insertion point IS the entry point, the entry point
        should NOT be updated - the inserted payload becomes the new entry code.
        """
        # Get current entry point
        entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        # Special case: if we're inserting AT the entry point, the entry point
        # should remain unchanged - the inserted payload IS the new entry code
        if insertion_rva is not None and entry_point == insertion_rva:
            print(f"  [EP] Entry Point is at insertion point 0x{entry_point:X} - keeping unchanged (payload becomes entry code)")
            return
        
        # Calculate shift for the entry point
        ep_shift = self._get_shift_for_rva(entry_point, shift_zones)
        
        if ep_shift == 0:
            return  # Entry point is not affected
        
        # Calculate new entry point
        new_entry_point = entry_point + ep_shift
        
        # Find the offset of AddressOfEntryPoint in the PE file
        # It's at offset 0x28 from the start of the Optional Header
        # Optional Header starts after DOS header + PE signature + File Header
        # 
        # DOS Header: pe.DOS_HEADER.e_lfanew points to PE signature
        # PE signature: 4 bytes ("PE\0\0")
        # File Header: 20 bytes (IMAGE_FILE_HEADER)
        # Optional Header starts at: e_lfanew + 4 + 20
        # AddressOfEntryPoint is at offset 0x10 in Optional Header (for both 32 and 64-bit)
        
        pe_sig_offset = self.pe.DOS_HEADER.e_lfanew
        optional_header_offset = pe_sig_offset + 4 + 20  # PE sig (4) + File Header (20)
        entry_point_offset = optional_header_offset + 0x10  # AddressOfEntryPoint offset
        
        # Update the entry point
        pe_data[entry_point_offset:entry_point_offset+4] = struct.pack('<I', new_entry_point)
        
        print(f"  [EP] Updated Entry Point: 0x{entry_point:X} -> 0x{new_entry_point:X}")
    
    def _update_data_directories_if_needed(self, pe_data: bytearray, shift_zones: List[ShiftZone]):
        """
        Update Data Directory RVA pointers if they point to shifted regions.
        
        Data Directories are pointers in the PE Optional Header that point to
        various metadata tables. When code/data shifts, these pointers must be
        updated to reflect the new locations.
        
        Directories that may need updating:
        - Export Directory (0)
        - Import Directory (1) 
        - Debug Directory (6)
        - TLS Directory (9)
        - Bound Import (11)
        - Import Address Table (12)
        - Delay Import Descriptor (13)
        
        Note: Exception Directory (3) and BaseReloc (5) are handled separately.
        Load Config (10) typically doesn't move as it's accessed early.
        """
        # Find offset of Data Directories in PE file
        # Data Directories are at the end of Optional Header
        pe_sig_offset = self.pe.DOS_HEADER.e_lfanew
        optional_header_offset = pe_sig_offset + 4 + 20  # PE sig (4) + File Header (20)
        
        # Optional Header size varies, but NumberOfRvaAndSizes is at fixed offset
        # For PE32+: Data directories start at offset 0x70 from Optional Header start
        # (after fixed fields + 16 bytes of additional header fields)
        if self.pe.OPTIONAL_HEADER.Magic == 0x20b:  # PE32+
            data_dir_offset = optional_header_offset + 0x70
        else:  # PE32
            data_dir_offset = optional_header_offset + 0x60
        
        # Each Data Directory entry is 8 bytes: VirtualAddress (4) + Size (4)
        directories_to_check = [
            (0, "Export"),
            (1, "Import"),
            (6, "Debug"),
            (9, "TLS"),
            (11, "BoundImport"),
            (12, "IAT"),
            (13, "DelayImport"),
        ]
        
        updates_made = []
        
        for dir_index, dir_name in directories_to_check:
            dir_entry_offset = data_dir_offset + dir_index * 8
            
            # Read current RVA and Size
            current_rva = struct.unpack('<I', pe_data[dir_entry_offset:dir_entry_offset+4])[0]
            current_size = struct.unpack('<I', pe_data[dir_entry_offset+4:dir_entry_offset+8])[0]
            
            if current_rva == 0:
                continue  # Directory not present
            
            # Check if this RVA needs updating
            shift = self._get_shift_for_rva(current_rva, shift_zones)
            
            if shift != 0:
                new_rva = current_rva + shift
                pe_data[dir_entry_offset:dir_entry_offset+4] = struct.pack('<I', new_rva)
                updates_made.append((dir_name, current_rva, new_rva))
        
        if updates_made:
            print(f"  [DataDir] Updated {len(updates_made)} Data Directory pointer(s):")
            for name, old_rva, new_rva in updates_made:
                print(f"    {name}: 0x{old_rva:X} -> 0x{new_rva:X}")
    
    def _perform_segmented_shift(self, pe_data: bytearray, content: bytes, shift_zones: List[ShiftZone]):
        """
        Perform segmented byte shifting where each zone shifts by a different amount.
        
        Process zones in reverse order to avoid overwriting data we still need to copy.
        """
        # Process zones in reverse order (from end to start)
        for zone in reversed(shift_zones):
            zone_start_offset = self.analyzer.rva_to_offset(zone.start_rva)
            zone_end_offset = self.analyzer.rva_to_offset(zone.end_rva)
            
            if zone_start_offset is None or zone_end_offset is None:
                continue
            
            # Get bytes in this zone
            zone_bytes = bytes(pe_data[zone_start_offset:zone_end_offset])
            zone_size = len(zone_bytes)
            
            # Write shifted bytes
            dest_offset = zone_start_offset + zone.shift_amount
            pe_data[dest_offset:dest_offset + zone_size] = zone_bytes
            
            print(f"    Zone 0x{zone.start_rva:X}-0x{zone.end_rva:X}: shifted {zone_size} bytes by {zone.shift_amount}")
        
        # Write the new content at insertion point
        insertion_offset = self.analyzer.rva_to_offset(shift_zones[0].start_rva) if shift_zones else None
        if insertion_offset is not None:
            pe_data[insertion_offset:insertion_offset + len(content)] = content
            print(f"    Inserted {len(content)} bytes at offset 0x{insertion_offset:X}")
    
    def _get_shift_for_rva(self, rva: int, shift_zones: List[ShiftZone]) -> int:
        """
        Get the shift amount for a given RVA based on shift zones.
        
        The shift amount decreases as we pass through each zone's absorbing padding.
        
        IMPORTANT: Shifts only apply to addresses within .text section.
        Addresses in .rdata, .data, etc. do NOT shift even if their RVA
        numerically falls within the shift zone range.
        
        Returns:
            - 0 if RVA is before the first zone (before insertion point)
            - 0 if RVA is outside .text section
            - zone.shift_amount if RVA is within a zone's range in .text
            - 0 if RVA is after all zones have absorbed the shift
        """
        if not shift_zones:
            return 0
        
        # CRITICAL: Only .text section addresses shift!
        # This prevents RVA values in .rdata/.data from being incorrectly
        # considered part of the shift zone when padding extends beyond .text.
        text_section = self.analyzer.get_text_section()
        if text_section:
            text_start = text_section['rva']
            text_end = text_start + text_section['virtual_size']
            if not (text_start <= rva < text_end):
                # RVA is outside .text section - no shift
                return 0
        
        # Before the first zone - no shift
        if rva < shift_zones[0].start_rva:
            return 0
        
        # Check each zone
        for i, zone in enumerate(shift_zones):
            # RVA is in this zone's code range
            if zone.start_rva <= rva < zone.end_rva:
                return zone.shift_amount
            
            # RVA is in this zone's absorbing padding
            # The padding region itself shifts by the same amount as the zone
            # But only if it's still within .text (checked above)
            padding_end = zone.absorbing_padding_rva + zone.absorbing_padding_size
            if zone.absorbing_padding_rva <= rva < padding_end:
                return zone.shift_amount
            
            # RVA is after this zone's absorbed padding but before next zone
            # This means it's in the "remaining" padding that wasn't absorbed
            if i + 1 < len(shift_zones):
                next_zone_start = shift_zones[i + 1].start_rva
                if padding_end <= rva < next_zone_start:
                    # This is in padding between zones - it shifts by the next zone's amount
                    return shift_zones[i + 1].shift_amount
        
        # After all zones - check if we're past the last absorption
        last_zone = shift_zones[-1]
        last_padding_end = last_zone.absorbing_padding_rva + last_zone.absorbing_padding_size
        if rva >= last_padding_end:
            return 0
        
        return 0
    
    def _fix_relative_reference(self, pe_data: bytearray, ref: Reference, 
                                 shift_zones: List[ShiftZone], debug_count: list = None) -> bool:
        """Fix a relative code reference using shift zones"""
        loc = ref.location_rva
        target = ref.target_rva
        
        loc_shift = self._get_shift_for_rva(loc, shift_zones)
        target_shift = self._get_shift_for_rva(target, shift_zones)
        
        # If both shift by the same amount, no change needed
        if loc_shift == target_shift:
            return False
        
        # Calculate delta
        delta = target_shift - loc_shift
        
        # Get file offset (accounting for shift if loc moved)
        ref_location = self.analyzer.rva_to_offset(loc)
        if ref_location is None:
            return False
        
        if loc_shift > 0:
            ref_location += loc_shift
        
        ref_value_offset = ref_location + ref.ref_offset
        
        # Apply delta
        if ref.ref_size == 1:
            current_offset = struct.unpack('<b', pe_data[ref_value_offset:ref_value_offset+1])[0]
            new_offset = current_offset + delta
            if new_offset < -128 or new_offset > 127:
                print(f"    WARNING: Short jump at 0x{loc:X} would overflow")
                return False
            pe_data[ref_value_offset:ref_value_offset+1] = struct.pack('<b', new_offset)
        elif ref.ref_size == 4:
            current_offset = struct.unpack('<i', pe_data[ref_value_offset:ref_value_offset+4])[0]
            new_offset = current_offset + delta
            pe_data[ref_value_offset:ref_value_offset+4] = struct.pack('<i', new_offset)
        else:
            return False
        
        return True
    
    def _fix_rip_relative_reference(self, pe_data: bytearray, ref: Reference,
                                     shift_zones: List[ShiftZone]) -> bool:
        """
        Fix a RIP-relative data reference using shift zones.
        
        RIP-relative addressing: disp32 = target_address - (instruction_address + instruction_size)
        
        Unlike control flow (call/jmp), RIP-relative needs fixing when:
        - Instruction moves but target doesn't (target outside .text, like .rdata)
        - Target moves but instruction doesn't (target in .text, like jump table)
        - Both move by different amounts (segmented absorption)
        
        The fix is: new_disp = old_disp + target_shift - loc_shift
                  = old_disp - (loc_shift - target_shift)
        """
        loc = ref.location_rva
        target = ref.target_rva
        
        loc_shift = self._get_shift_for_rva(loc, shift_zones)
        target_shift = self._get_shift_for_rva(target, shift_zones)
        
        # If both shift by the same amount, disp32 stays valid
        if loc_shift == target_shift:
            return False
        
        # Calculate how the displacement needs to change
        # new_target = target + target_shift
        # new_insn_end = (loc + insn_size) + loc_shift
        # new_disp = new_target - new_insn_end
        #          = (target + target_shift) - ((loc + insn_size) + loc_shift)
        #          = (target - (loc + insn_size)) + (target_shift - loc_shift)
        #          = old_disp + (target_shift - loc_shift)
        delta = target_shift - loc_shift
        
        # Get file offset (accounting for shift if instruction moved)
        ref_location = self.analyzer.rva_to_offset(loc)
        if ref_location is None:
            return False
        
        if loc_shift > 0:
            ref_location += loc_shift
        
        ref_value_offset = ref_location + ref.ref_offset
        
        # RIP-relative always uses disp32
        current_disp = struct.unpack('<i', pe_data[ref_value_offset:ref_value_offset+4])[0]
        new_disp = current_disp + delta
        pe_data[ref_value_offset:ref_value_offset+4] = struct.pack('<i', new_disp)
        
        return True
    
    def _fix_absolute_reference(self, pe_data: bytearray, ref: Reference,
                                 shift_zones: List[ShiftZone]) -> bool:
        """Fix an absolute reference using shift zones"""
        target_shift = self._get_shift_for_rva(ref.target_rva, shift_zones)
        
        if target_shift == 0:
            return False
        
        ref_offset = self.analyzer.rva_to_offset(ref.location_rva)
        if ref_offset is None:
            return False
        
        if ref.ref_size == 8:
            current_va = struct.unpack('<Q', pe_data[ref_offset:ref_offset+8])[0]
            new_va = current_va + target_shift
            pe_data[ref_offset:ref_offset+8] = struct.pack('<Q', new_va)
        elif ref.ref_size == 4:
            current_va = struct.unpack('<I', pe_data[ref_offset:ref_offset+4])[0]
            new_va = current_va + target_shift
            pe_data[ref_offset:ref_offset+4] = struct.pack('<I', new_va)
        else:
            return False
        
        return True
    
    def _fix_metadata_reference(self, pe_data: bytearray, ref: Reference,
                                 shift_zones: List[ShiftZone]) -> bool:
        """Fix a metadata reference using shift zones"""
        target_shift = self._get_shift_for_rva(ref.target_rva, shift_zones)
        
        if target_shift == 0:
            return False
        
        ref_offset = self.analyzer.rva_to_offset(ref.location_rva)
        if ref_offset is None:
            return False
        
        if ref.ref_size == 4:
            current_rva = struct.unpack('<I', pe_data[ref_offset:ref_offset+4])[0]
            new_rva = current_rva + target_shift
            pe_data[ref_offset:ref_offset+4] = struct.pack('<I', new_rva)
        elif ref.ref_size == 8:
            current_va = struct.unpack('<Q', pe_data[ref_offset:ref_offset+8])[0]
            new_va = current_va + target_shift
            pe_data[ref_offset:ref_offset+8] = struct.pack('<Q', new_va)
        else:
            return False
        
        return True
    
    def _fix_cfg_reference(self, pe_data: bytearray, ref: Reference,
                           shift_zones: List[ShiftZone]) -> bool:
        """Fix a CFG reference using shift zones"""
        target_shift = self._get_shift_for_rva(ref.target_rva, shift_zones)
        
        if target_shift == 0:
            return False
        
        ref_offset = self.analyzer.rva_to_offset(ref.location_rva)
        if ref_offset is None:
            return False
        
        current_rva = struct.unpack('<I', pe_data[ref_offset:ref_offset+4])[0]
        new_rva = current_rva + target_shift
        pe_data[ref_offset:ref_offset+4] = struct.pack('<I', new_rva)
        
        return True
    
    def _fix_jump_table_reference(self, pe_data: bytearray, ref: Reference,
                                   shift_zones: List[ShiftZone]) -> bool:
        """
        Fix a jump table entry or function pointer reference using shift zones.
        
        Handles multiple types of references:
        1. 32-bit RVA (JUMP_TABLE_ENTRY, FUNC_PTR_RVA): RVA stored in data sections
        2. 64-bit VA (VA_PTR_64): Absolute address in RELOCS_STRIPPED executables
        3. DISP32_TEXT_PTR: Memory operand displacement pointing to .text
        
        IMPORTANT: For references located in .text (inline jump tables or DISP32), the 
        reference location itself moves when code shifts. We must account for
        this by adjusting the file offset.
        """
        target_shift = self._get_shift_for_rva(ref.target_rva, shift_zones)
        location_shift = self._get_shift_for_rva(ref.location_rva, shift_zones)
        
        # For DISP32_TEXT_PTR, the displacement is an ABSOLUTE address in the instruction
        # (not RIP-relative). When the target location in .text shifts, the displacement
        # must be updated to point to the new location.
        # Unlike RIP-relative where both instruction and target shift cancel out,
        # here the displacement is absolute and must track the target's movement.
        if ref.ref_type == RefType.DISP32_TEXT_PTR:
            # The displacement must be updated by target_shift
            # (instruction movement doesn't affect absolute displacement)
            if target_shift == 0:
                return False
            
            # Get file offset (accounting for instruction shift)
            ref_offset = self.analyzer.rva_to_offset(ref.location_rva)
            if ref_offset is None:
                return False
            
            if location_shift > 0:
                ref_offset += location_shift
            
            # The disp32 is at ref.ref_offset within the instruction
            disp_offset = ref_offset + ref.ref_offset
            
            # Read current displacement (absolute address)
            current_disp = struct.unpack('<I', pe_data[disp_offset:disp_offset+4])[0]
            # Apply target_shift to update to new location
            new_disp = current_disp + target_shift
            pe_data[disp_offset:disp_offset+4] = struct.pack('<I', new_disp)
            
            return True
        
        # For other types, target must shift for a fix to be needed
        if target_shift == 0:
            return False
        
        # Get original file offset
        ref_offset = self.analyzer.rva_to_offset(ref.location_rva)
        if ref_offset is None:
            return False
        
        # Check if the reference location itself has shifted
        # This happens for inline jump tables embedded in .text
        if location_shift > 0:
            # The reference moved - adjust file offset to its NEW position
            ref_offset += location_shift
        
        # Handle based on reference type/size
        if ref.ref_size == 8 or ref.ref_type == RefType.VA_PTR_64:
            # 64-bit VA pointer
            current_va = struct.unpack('<Q', pe_data[ref_offset:ref_offset+8])[0]
            new_va = current_va + target_shift
            pe_data[ref_offset:ref_offset+8] = struct.pack('<Q', new_va)
        else:
            # 32-bit RVA (default case for jump tables)
            current_rva = struct.unpack('<I', pe_data[ref_offset:ref_offset+4])[0]
            new_rva = current_rva + target_shift
            pe_data[ref_offset:ref_offset+4] = struct.pack('<I', new_rva)
        
        return True
        
        return True
        


# ============================================================================
# Report Generator
# ============================================================================

def generate_impact_report(analysis: ImpactAnalysis, text_info: dict, analyzer: PEAnalyzer) -> str:
    """Generate a human-readable impact analysis report with RVA and file offsets"""
    lines = []
    lines.append("=" * 70)
    lines.append("PE BYTE INSERTION IMPACT ANALYSIS (Method 3)")
    lines.append("=" * 70)
    lines.append("")
    
    # Section info
    if text_info:
        lines.append(f".text Section Info:")
        lines.append(f"  RVA:          0x{text_info.get('rva', 0):08X}")
        lines.append(f"  VirtualSize:  0x{text_info.get('virtual_size', 0):X} ({text_info.get('virtual_size', 0)} bytes)")
        lines.append(f"  RawSize:      0x{text_info.get('raw_size', 0):X} ({text_info.get('raw_size', 0)} bytes)")
        lines.append(f"  RawOffset:    0x{text_info.get('raw_offset', 0):X}")
        raw_end = text_info.get('raw_offset', 0) + text_info.get('raw_size', 0)
        lines.append(f"  RawEnd:       0x{raw_end:X}")
        lines.append("")
    
    # Insertion info with both RVA and file offset
    insertion_offset = analyzer.rva_to_offset(analysis.insertion_rva)
    affected_end_offset = analyzer.rva_to_offset(analysis.affected_range_end)
    
    lines.append(f"Insertion Point:     {format_addr(analysis.insertion_rva, insertion_offset)}")
    lines.append(f"Insertion Size:      {analysis.insertion_size} bytes")
    lines.append(f"Affected Range:      {format_addr(analysis.affected_range_start, insertion_offset)}")
    lines.append(f"                  to {format_addr(analysis.affected_range_end, affected_end_offset)}")
    lines.append("")
    
    # Padding analysis - detailed breakdown
    lines.append(f"Padding Analysis:")
    
    # Calculate internal vs trailing padding
    internal_padding = 0
    trailing_padding = analysis.trailing_padding
    internal_regions = []
    
    if analysis.padding_regions:
        # If there's trailing padding, it's the last region (or part of it)
        if trailing_padding > 0:
            # All regions except possibly the last one are internal
            for rva, size in analysis.padding_regions[:-1]:
                internal_padding += size
                internal_regions.append((rva, size))
            # Check if last region is entirely trailing or mixed
            if len(analysis.padding_regions) > 0:
                last_rva, last_size = analysis.padding_regions[-1]
                if last_size > trailing_padding:
                    # Part of last region is internal
                    internal_part = last_size - trailing_padding
                    internal_padding += internal_part
                    internal_regions.append((last_rva, internal_part))
        else:
            # All regions are internal
            for rva, size in analysis.padding_regions:
                internal_padding += size
                internal_regions.append((rva, size))
    
    lines.append(f"  Total Available:   {analysis.available_padding} bytes (0x{analysis.available_padding:X})")
    lines.append("")
    
    # Show individual free byte sequences (first 10)
    if internal_regions:
        lines.append(f"  Free Byte Sequences (before .text tail):")
        for i, (rva, size) in enumerate(internal_regions[:10]):
            offset = analyzer.rva_to_offset(rva)
            lines.append(f"    Sequence {i+1}: {size} bytes at {format_addr_short(rva, offset)}")
        if len(internal_regions) > 10:
            lines.append(f"    ... and {len(internal_regions) - 10} more sequences")
        lines.append("")
        lines.append(f"  Total internal padding (before .text tail): {internal_padding} bytes (0x{internal_padding:X})")
    else:
        lines.append(f"  Internal padding (before .text tail): 0 bytes")
    
    lines.append(f"  Trailing padding (.text tail):          {trailing_padding} bytes (0x{trailing_padding:X})")
    lines.append("")
    
    lines.append(f"Section Expansion:   {'⚠️  REQUIRED' if analysis.needs_section_expansion else '✅ Not needed'}")
    lines.append("")
    
    # Shift Zones and Strategy
    lines.append("-" * 70)
    lines.append("SHIFT STRATEGY")
    lines.append("-" * 70)
    
    if analysis.shift_zones:
        if analysis.use_segmented_absorption:
            lines.append(f"\n✨ SEGMENTED ABSORPTION ({len(analysis.shift_zones)} zones)")
            lines.append("   Function-internal padding can absorb all inserted bytes.")
            lines.append("   This minimizes references to fix - .text trailing space untouched.")
        else:
            lines.append(f"\n📦 SIMPLE WHOLE-SHIFT")
            lines.append("   Function-internal padding insufficient - shifting to .text end.")
            lines.append("   This is simpler when trailing space is needed anyway.")
        
        lines.append("")
        lines.append("  Shift Zones:")
        for i, zone in enumerate(analysis.shift_zones):
            zone_start_offset = analyzer.rva_to_offset(zone.start_rva)
            zone_end_offset = analyzer.rva_to_offset(zone.end_rva)
            padding_offset = analyzer.rva_to_offset(zone.absorbing_padding_rva)
            lines.append(f"    Zone {i+1}: {format_addr_short(zone.start_rva, zone_start_offset)} - {format_addr_short(zone.end_rva, zone_end_offset)}")
            lines.append(f"            Shift: {zone.shift_amount} bytes → absorbed by {zone.absorbing_padding_size} bytes at {format_addr_short(zone.absorbing_padding_rva, padding_offset)}")
    else:
        lines.append("\n⚠️  No shift zones computed")
    
    lines.append("")
    
    # CFG Analysis
    lines.append("-" * 70)
    lines.append("CONTROL FLOW GUARD (CFG) ANALYSIS")
    lines.append("-" * 70)
    
    if analysis.cfg_info:
        cfg = analysis.cfg_info
        if cfg.enabled or cfg.instrumented:
            lines.append(f"\n⚠️  CFG IS ENABLED - Additional modifications required!")
            lines.append(f"  CFG Enabled:       {cfg.enabled}")
            lines.append(f"  CFG Instrumented:  {cfg.instrumented}")
            lines.append(f"  Guard Flags:       0x{cfg.guard_flags:08X}")
            lines.append("")
            
            if cfg.function_count > 0:
                func_offset = analyzer.rva_to_offset(cfg.function_table_rva) if cfg.function_table_rva else None
                lines.append(f"  GuardCFFunctionTable:")
                lines.append(f"    Location:  {format_addr(cfg.function_table_rva, func_offset)}")
                lines.append(f"    Count:     {cfg.function_count} entries")
            
            if cfg.iat_entry_count > 0:
                iat_offset = analyzer.rva_to_offset(cfg.iat_entry_table_rva) if cfg.iat_entry_table_rva else None
                lines.append(f"  GuardAddressTakenIatEntryTable:")
                lines.append(f"    Location:  {format_addr(cfg.iat_entry_table_rva, iat_offset)}")
                lines.append(f"    Count:     {cfg.iat_entry_count} entries")
            
            if cfg.longjmp_count > 0:
                lj_offset = analyzer.rva_to_offset(cfg.longjmp_table_rva) if cfg.longjmp_table_rva else None
                lines.append(f"  GuardLongJumpTargetTable:")
                lines.append(f"    Location:  {format_addr(cfg.longjmp_table_rva, lj_offset)}")
                lines.append(f"    Count:     {cfg.longjmp_count} entries")
            
            if cfg.ehcont_count > 0:
                eh_offset = analyzer.rva_to_offset(cfg.ehcont_table_rva) if cfg.ehcont_table_rva else None
                lines.append(f"  GuardEHContinuationTable:")
                lines.append(f"    Location:  {format_addr(cfg.ehcont_table_rva, eh_offset)}")
                lines.append(f"    Count:     {cfg.ehcont_count} entries")
            
            lines.append("")
            lines.append(f"  CFG References in affected range: {len(analysis.cfg_refs)}")
            if analysis.cfg_refs:
                cfg_by_type = {}
                for ref in analysis.cfg_refs:
                    cfg_by_type.setdefault(ref.ref_type.name, []).append(ref)
                for rtype, refs in cfg_by_type.items():
                    lines.append(f"    {rtype}: {len(refs)}")
        else:
            lines.append("\n✅ CFG is NOT enabled - no CFG tables to modify")
    else:
        lines.append("\n✅ No CFG information found")
    
    lines.append("")
    
    # Chain reaction
    lines.append("-" * 70)
    lines.append("CHAIN REACTION ANALYSIS")
    lines.append("-" * 70)
    
    if analysis.short_jumps_needing_expansion:
        lines.append(f"\n⚠️  {len(analysis.short_jumps_needing_expansion)} short jump(s) will overflow:")
        lines.append(f"    Extra bytes needed: {analysis.chain_reaction_extra_bytes}")
        for ref in analysis.short_jumps_needing_expansion[:10]:
            loc_offset = analyzer.rva_to_offset(ref.location_rva)
            target_offset = analyzer.rva_to_offset(ref.target_rva)
            lines.append(f"    {format_addr_short(ref.location_rva, loc_offset)} -> {format_addr_short(ref.target_rva, target_offset)}")
        if len(analysis.short_jumps_needing_expansion) > 10:
            lines.append(f"    ... and {len(analysis.short_jumps_needing_expansion) - 10} more")
    else:
        lines.append("\n✅ No short jump overflow (no chain reaction)")
    
    lines.append("")
    
    # References
    lines.append("-" * 70)
    lines.append("REFERENCES REQUIRING MODIFICATION")
    lines.append("-" * 70)
    
    # Relative control flow references (call/jmp/jcc)
    lines.append(f"\n[Relative Code References: {len(analysis.relative_refs)}]")
    ref_by_type = {}
    for ref in analysis.relative_refs:
        ref_by_type.setdefault(ref.ref_type.name, []).append(ref)
    for rtype, refs in ref_by_type.items():
        lines.append(f"  {rtype}: {len(refs)}")
        for ref in refs[:5]:
            loc_offset = analyzer.rva_to_offset(ref.location_rva)
            target_offset = analyzer.rva_to_offset(ref.target_rva)
            lines.append(f"    {format_addr_short(ref.location_rva, loc_offset)} -> {format_addr_short(ref.target_rva, target_offset)}")
        if len(refs) > 5:
            lines.append(f"    ... and {len(refs) - 5} more")
    
    # RIP-relative data references
    lines.append(f"\n[RIP-Relative References: {len(analysis.rip_relative_refs)}]")
    if analysis.rip_relative_refs:
        lines.append("  (memory operands: data access, IAT calls, indirect jumps)")
        for ref in analysis.rip_relative_refs[:10]:
            loc_offset = analyzer.rva_to_offset(ref.location_rva)
            target_offset = analyzer.rva_to_offset(ref.target_rva)
            lines.append(f"    {format_addr_short(ref.location_rva, loc_offset)} -> {format_addr_short(ref.target_rva, target_offset)}")
        if len(analysis.rip_relative_refs) > 10:
            lines.append(f"    ... and {len(analysis.rip_relative_refs) - 10} more")
    
    # Absolute references
    lines.append(f"\n[Absolute References (Relocations): {len(analysis.absolute_refs)}]")
    for ref in analysis.absolute_refs[:10]:
        loc_offset = analyzer.rva_to_offset(ref.location_rva)
        target_offset = analyzer.rva_to_offset(ref.target_rva)
        lines.append(f"  {format_addr_short(ref.location_rva, loc_offset)} -> {format_addr_short(ref.target_rva, target_offset)}")
    if len(analysis.absolute_refs) > 10:
        lines.append(f"  ... and {len(analysis.absolute_refs) - 10} more")
    
    # Metadata references
    lines.append(f"\n[Metadata Table References: {len(analysis.metadata_refs)}]")
    meta_by_type = {}
    for ref in analysis.metadata_refs:
        meta_by_type.setdefault(ref.ref_type.name, []).append(ref)
    for rtype, refs in meta_by_type.items():
        lines.append(f"  {rtype}: {len(refs)}")
        for ref in refs[:3]:
            loc_offset = analyzer.rva_to_offset(ref.location_rva)
            target_offset = analyzer.rva_to_offset(ref.target_rva)
            lines.append(f"    {format_addr_short(ref.location_rva, loc_offset)} -> {format_addr_short(ref.target_rva, target_offset)}")
        if len(refs) > 3:
            lines.append(f"    ... and {len(refs) - 3} more")
    
    # Jump table references (including function pointers and VA pointers)
    if analysis.jump_table_refs:
        # Separate by type
        rva_refs = [r for r in analysis.jump_table_refs if r.ref_size == 4]
        va_refs = [r for r in analysis.jump_table_refs if r.ref_size == 8 or r.ref_type == RefType.VA_PTR_64]
        
        lines.append(f"\n[Data Section Pointer References: {len(analysis.jump_table_refs)}]")
        if rva_refs:
            lines.append(f"  32-bit RVA pointers (jump tables, func ptrs): {len(rva_refs)}")
        if va_refs:
            lines.append(f"  64-bit VA pointers (vtables, RELOCS_STRIPPED): {len(va_refs)}")
        
        # Group by base address for display
        jt_groups = {}
        for ref in analysis.jump_table_refs:
            base = (ref.location_rva // 16) * 16
            jt_groups.setdefault(base, []).append(ref)
        
        lines.append(f"  Pointer groups affected: {len(jt_groups)}")
        for base_rva in sorted(jt_groups.keys())[:5]:
            refs = jt_groups[base_rva]
            first_ref = min(refs, key=lambda r: r.location_rva)
            base_offset = analyzer.rva_to_offset(first_ref.location_rva)
            ptr_type = "64-bit" if any(r.ref_size == 8 for r in refs) else "32-bit"
            lines.append(f"    Group at {format_addr_short(first_ref.location_rva, base_offset)}: {len(refs)} {ptr_type} entries")
        if len(jt_groups) > 5:
            lines.append(f"    ... and {len(jt_groups) - 5} more groups")
    
    # Summary
    lines.append("")
    lines.append("-" * 70)
    lines.append("SUMMARY")
    lines.append("-" * 70)
    
    total_refs = (len(analysis.relative_refs) + len(analysis.rip_relative_refs) +
                  len(analysis.absolute_refs) + len(analysis.metadata_refs) + 
                  len(analysis.cfg_refs) + len(analysis.jump_table_refs))
    total_bytes = analysis.insertion_size + analysis.chain_reaction_extra_bytes
    
    lines.append(f"Total references to fix: {total_refs}")
    if analysis.rip_relative_refs:
        lines.append(f"  (includes {len(analysis.rip_relative_refs)} RIP-relative data accesses)")
    if analysis.cfg_refs:
        lines.append(f"  (includes {len(analysis.cfg_refs)} CFG entries)")
    if analysis.jump_table_refs:
        lines.append(f"  (includes {len(analysis.jump_table_refs)} jump table entries)")
    lines.append(f"Total bytes to insert:   {total_bytes} (original: {analysis.insertion_size}, chain reaction: {analysis.chain_reaction_extra_bytes})")
    
    # Feasibility verdict
    lines.append("")
    lines.append("-" * 70)
    lines.append("FEASIBILITY VERDICT")
    lines.append("-" * 70)
    
    if analysis.is_feasible:
        lines.append("\n✅ METHOD 3 INSERTION IS FEASIBLE")
        lines.append("   Padding available is sufficient to absorb the insertion.")
        lines.append("   Use -o <output.exe> to perform the actual insertion.")
    else:
        lines.append("\n❌ METHOD 3 INSERTION IS NOT FEASIBLE")
        for reason in analysis.blocking_reasons:
            lines.append(f"   • {reason}")
        lines.append("\n   Consider using Method 1 (new section) or Method 2 (code cave) instead.")
    
    if analysis.cfg_info and (analysis.cfg_info.enabled or analysis.cfg_info.instrumented):
        if analysis.is_feasible:
            lines.append("\n⚠️  NOTE: CFG is enabled - CFG tables will be updated automatically.")
    
    lines.append("")
    return "\n".join(lines)


def print_validation_report(validation: PEValidation, pe: pefile.PE):
    """Print PE validation report"""
    print("=" * 70)
    print("PE VALIDATION REPORT")
    print("=" * 70)
    print()
    
    # Basic info
    print(f"Architecture:     {'x64 (AMD64)' if validation.is_64bit else 'x86 (i386)'}")
    print(f"Has .text:        {'✅ Yes' if validation.has_text_section else '❌ No'}")
    print(f"Detected Compiler: {validation.detected_compiler}")
    print()
    
    # Sections list
    print("Sections:")
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        chars = section.Characteristics
        flags = []
        if chars & 0x20000000: flags.append("EXEC")
        if chars & 0x40000000: flags.append("READ")
        if chars & 0x80000000: flags.append("WRITE")
        print(f"  {name:12} RVA: 0x{section.VirtualAddress:08X}  Size: 0x{section.Misc_VirtualSize:08X}  [{', '.join(flags)}]")
    print()
    
    # Vanilla check
    if validation.is_likely_vanilla:
        print("✅ PE appears to be a vanilla C/C++ executable")
    else:
        print("⚠️  PE may NOT be a vanilla C/C++ executable!")
        if validation.suspicious_sections:
            print(f"   Suspicious sections: {', '.join(validation.suspicious_sections)}")
    print()
    
    # Warnings
    if validation.warnings:
        print("Warnings:")
        for warning in validation.warnings:
            print(f"  ⚠️  {warning}")
        print()
    
    # Overall verdict
    if validation.is_valid and validation.is_likely_vanilla:
        print("✅ VERDICT: Safe to patch with this tool")
    elif validation.is_valid:
        print("⚠️  VERDICT: Patching possible but may have issues - proceed with caution")
    else:
        print("❌ VERDICT: Cannot patch - PE is invalid or unsupported")
    
    print("=" * 70)
    print()


# ============================================================================
# Main CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PE Byte Inserter v2 - Insert bytes into PE executables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate PE before patching
  python BScalpel.py input.exe --validate

  # Method 1: New section injection
  python BScalpel.py input.exe -m 1 -a 0x1000 -c "xor rax, rax; ret" -o output.exe

  # Method 2: Code cave injection (uses LARGEST cave)
  python BScalpel.py input.exe -m 2 -a 0x1000 -b payload.bin -o output.exe

  # Method 3: Quick test - insert 480 NOPs at Entry Point (auto-named output)
  python BScalpel.py input.exe -m 3 -n 480

  # Method 3: Insert at specific address with custom output
  python BScalpel.py input.exe -m 3 -a 0x1000 -n 16 -o patched.exe

  # Method 3: Analysis only (no insertion)
  python BScalpel.py input.exe -m 3 -a 0x1000 -s 100

  # List code caves (sorted by size)
  python BScalpel.py input.exe --list-caves

  # Analyze all references
  python BScalpel.py input.exe --analyze
        """
    )
    
    parser.add_argument("exe", help="Input PE executable")
    parser.add_argument("-m", "--method", type=int, choices=[1, 2, 3],
                        help="Injection method: 1=New section, 2=Code cave (largest), 3=Analysis only")
    parser.add_argument("-a", "--address", type=str,
                        help="Injection/hook RVA (hex, e.g., 0x1000). Method 3 defaults to Entry Point if not specified")
    parser.add_argument("-o", "--output", help="Output PE file. Method 3 auto-generates if not specified")
    
    # Payload options
    payload_group = parser.add_mutually_exclusive_group()
    payload_group.add_argument("-b", "--bin", help="Binary file containing payload")
    payload_group.add_argument("-c", "--code", help="Assembly code string (e.g., 'xor rax, rax; ret')")
    payload_group.add_argument("-x", "--hex", help="Hex string payload (e.g., '4831C0C3')")
    
    # Method 3 specific
    parser.add_argument("-s", "--size", type=int, default=0,
                        help="Insertion size for analysis (method 3)")
    parser.add_argument("-n", "--nop", type=int, default=0,
                        help="Test mode: insert N NOP bytes (0x90) at address (method 3)")
    
    # Utility options
    parser.add_argument("--validate", action="store_true",
                        help="Validate PE and check if suitable for patching")
    parser.add_argument("--list-caves", action="store_true",
                        help="List all code caves (sorted by size, largest first)")
    parser.add_argument("--cave-section", type=str, default=None,
                        help="Filter caves by section name (e.g., .text, .data). Default: all sections")
    parser.add_argument("--cave-top", type=int, default=None,
                        help="Show only top N largest caves (strict, no ties)")
    parser.add_argument("--analyze", action="store_true",
                        help="Analyze and list all references in the PE")
    parser.add_argument("--disasm", type=str,
                        help="Disassemble at RVA (hex) for N bytes, format: RVA:SIZE")
    parser.add_argument("--cfg", action="store_true",
                        help="Show CFG (Control Flow Guard) information")
    parser.add_argument("--debug", action="store_true",
                        help="Show debug information for troubleshooting")
    
    args = parser.parse_args()
    
    # Load PE
    try:
        pe = pefile.PE(args.exe)
    except Exception as e:
        print(f"Error loading PE: {e}")
        return 1
    
    analyzer = PEAnalyzer(pe)
    
    # Always validate first
    validator = PEValidator(pe)
    validation = validator.validate()
    
    # Handle --validate
    if args.validate:
        print_validation_report(validation, pe)
        return 0 if validation.is_valid else 1
    
    # Show brief validation warning if not vanilla
    if not validation.is_likely_vanilla:
        print("⚠️  WARNING: PE may not be a vanilla C/C++ executable!")
        if validation.suspicious_sections:
            print(f"   Suspicious sections: {', '.join(validation.suspicious_sections)}")
        for warning in validation.warnings[:3]:
            print(f"   {warning}")
        print("   Use --validate for full report")
        print()
    
    # Handle --cfg
    if args.cfg:
        cfg_refs, cfg_info = analyzer.collect_cfg_references()
        print("Control Flow Guard (CFG) Information:")
        print("=" * 50)
        if cfg_info.enabled or cfg_info.instrumented:
            print(f"CFG Enabled:       {cfg_info.enabled}")
            print(f"CFG Instrumented:  {cfg_info.instrumented}")
            print(f"Guard Flags:       0x{cfg_info.guard_flags:08X}")
            print()
            print(f"GuardCFFunctionTable:     {cfg_info.function_count} entries at RVA 0x{cfg_info.function_table_rva:X}")
            print(f"GuardIatEntryTable:       {cfg_info.iat_entry_count} entries at RVA 0x{cfg_info.iat_entry_table_rva:X}")
            print(f"GuardLongJumpTargetTable: {cfg_info.longjmp_count} entries at RVA 0x{cfg_info.longjmp_table_rva:X}")
            print(f"GuardEHContinuationTable: {cfg_info.ehcont_count} entries at RVA 0x{cfg_info.ehcont_table_rva:X}")
        else:
            print("CFG is NOT enabled for this PE")
        return 0
    
    # Handle --list-caves
    if args.list_caves:
        section_filter = args.cave_section
        top_n = args.cave_top
        
        # Build title
        title_parts = ["Code Caves Found"]
        if section_filter:
            title_parts.append(f"in {section_filter}")
        title_parts.append("(sorted by size, largest first)")
        if top_n:
            title_parts.append(f"- Top {top_n}")
        
        print(" ".join(title_parts) + ":")
        print("-" * 70)
        
        caves = analyzer.find_code_caves(min_size=8, section_filter=section_filter)
        
        # Apply top N filter (strict, no ties)
        if top_n is not None and top_n > 0:
            caves = caves[:top_n]
        
        if not caves:
            if section_filter:
                print(f"  No caves found in section '{section_filter}'")
            else:
                print("  No caves found")
            return 0
        
        total_space = sum(c.size for c in caves)
        for i, cave in enumerate(caves):
            marker = " ← LARGEST" if i == 0 else ""
            print(f"  RVA: 0x{cave.rva:08X} (File: 0x{cave.file_offset:06X})  Size: {cave.size:6d}  Section: {cave.section_name}{marker}")
        
        print(f"\nShowing: {len(caves)} caves")
        if caves:
            print(f"Largest cave: {caves[0].size} bytes in {caves[0].section_name}")
            print(f"  → Maximum payload for Method 2: {caves[0].size - 15} bytes (minus trampoline overhead)")
            print(f"Total available space (shown caves): {total_space} bytes")
        return 0
    
    # Handle --analyze
    if args.analyze:
        print("Reference Analysis:")
        print("=" * 60)
        refs = analyzer.collect_all_references()
        for category, ref_list in refs.items():
            print(f"\n[{category.upper()}] - {len(ref_list)} references")
            for ref in ref_list[:5]:
                loc_offset = analyzer.rva_to_offset(ref.location_rva)
                target_offset = analyzer.rva_to_offset(ref.target_rva)
                print(f"  {ref.ref_type.name}: {format_addr_short(ref.location_rva, loc_offset)} -> {format_addr_short(ref.target_rva, target_offset)}")
            if len(ref_list) > 5:
                print(f"  ... and {len(ref_list) - 5} more")
        return 0
    
    # Handle --disasm
    if args.disasm:
        try:
            parts = args.disasm.split(':')
            rva = int(parts[0], 16)
            size = int(parts[1]) if len(parts) > 1 else 32
        except:
            print("Invalid disasm format. Use RVA:SIZE (e.g., 0x1000:32)")
            return 1
        
        offset = analyzer.rva_to_offset(rva)
        if offset is None:
            print(f"Cannot resolve RVA 0x{rva:X}")
            return 1
        
        code = pe.__data__[offset:offset+size]
        helper = AssemblyHelper()
        print(f"Disassembly at RVA 0x{rva:X} (File: 0x{offset:X}):")
        print("-" * 40)
        for line in helper.disassemble(code, rva):
            print(line)
        return 0
    
    # Methods 1 and 2 require address; Method 3 defaults to Entry Point
    if args.method in [1, 2] and not args.address:
        print("Error: --address required for methods 1 and 2")
        return 1
    
    hook_rva = None
    if args.address:
        try:
            hook_rva = int(args.address, 16)
        except:
            print(f"Invalid address format: {args.address}")
            return 1
    elif args.method == 3:
        # Default to Entry Point for Method 3
        hook_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print(f"No address specified, using Entry Point: 0x{hook_rva:X}")
    
    # Get payload for methods 1, 2, and 3 (when performing insertion)
    payload = None
    if args.nop and args.nop > 0:
        # Test mode: generate N NOP bytes
        payload = b'\x90' * args.nop
        print(f"Test mode: generating {args.nop} NOP bytes")
    elif args.bin:
        with open(args.bin, 'rb') as f:
            payload = f.read()
    elif args.code:
        helper = AssemblyHelper()
        payload = helper.assemble(args.code)
        print(f"Assembled: {payload.hex()}")
    elif args.hex:
        payload = bytes.fromhex(args.hex.replace(' ', ''))
    
    # Validate payload for methods 1 and 2
    if args.method in [1, 2] and not payload:
        print("Error: Payload required for methods 1 and 2 (-b, -c, or -x)")
        return 1
    
    # Execute method
    if args.method == 1:
        hook_offset = analyzer.rva_to_offset(hook_rva)
        print(f"Method 1: New Section Injection")
        print(f"Hook Point: {format_addr(hook_rva, hook_offset)}")
        print(f"Payload size: {len(payload)} bytes")
        
        injector = NewSectionInjector(pe)
        result = injector.inject(hook_rva, payload)
        
        output = args.output or args.exe.replace('.exe', '_patched.exe')
        with open(output, 'wb') as f:
            f.write(result)
        print(f"Output: {output}")
        
    elif args.method == 2:
        hook_offset = analyzer.rva_to_offset(hook_rva)
        print(f"Method 2: Code Cave Injection (using LARGEST cave)")
        print(f"Hook Point: {format_addr(hook_rva, hook_offset)}")
        print(f"Payload size: {len(payload)} bytes")
        
        caves = analyzer.find_code_caves(min_size=len(payload) + 20)
        if not caves:
            print("Error: No suitable code cave found")
            return 1
        
        # Use largest cave (first in sorted list)
        largest_cave = caves[0]
        print(f"Using LARGEST cave: {format_addr(largest_cave.rva, largest_cave.file_offset)} ({largest_cave.size} bytes in {largest_cave.section_name})")
        print(f"Maximum payload capacity: {largest_cave.size - 15} bytes (cave size minus trampoline overhead)")
        
        injector = CodeCaveInjector(pe)
        result = injector.inject(hook_rva, payload, largest_cave)
        
        output = args.output or args.exe.replace('.exe', '_patched.exe')
        with open(output, 'wb') as f:
            f.write(result)
        print(f"Output: {output}")
        
    elif args.method == 3:
        # Determine size from payload or --size argument
        if payload:
            size = len(payload)
        elif args.size > 0:
            size = args.size
        else:
            print("Error: --size or payload (-b, -c, -x) required for method 3")
            return 1
        
        hook_offset = analyzer.rva_to_offset(hook_rva)
        print(f"Method 3: In-Place Byte Insertion")
        print(f"Insertion Point: {format_addr(hook_rva, hook_offset)}")
        print(f"Insertion size: {size} bytes")
        print()
        
        # Perform impact analysis
        impact_analyzer = ImpactAnalyzer(analyzer)
        analysis = impact_analyzer.analyze(hook_rva, size, debug=getattr(args, 'debug', False))
        
        text_info = analyzer.get_text_section()
        
        report = generate_impact_report(analysis, text_info, analyzer)
        print(report)
        
        # If output specified and payload provided, perform actual insertion
        if payload:
            # Generate output filename if not specified
            if args.output:
                output_path = args.output
            else:
                # Auto-generate: originalname_0xADDRESS_SIZEbytes.exe
                # Use basename to avoid writing to read-only source directory
                base_name = os.path.splitext(os.path.basename(args.exe))[0]
                ext = os.path.splitext(args.exe)[1] or '.exe'
                output_path = f"{base_name}_0x{hook_rva:X}_{size}bytes{ext}"
                print(f"Output file: {output_path}")
            
            if not analysis.is_feasible:
                print("=" * 70)
                print("❌ CANNOT PERFORM INSERTION")
                print("=" * 70)
                print("The insertion is not feasible for the reasons listed above.")
                print("Consider using Method 1 or Method 2 instead:")
                print(f"  Method 1: python pe_inserter_v2.py {args.exe} -m 1 -a {args.address} ...")
                print(f"  Method 2: python pe_inserter_v2.py {args.exe} -m 2 -a {args.address} ...")
                return 1
            
            print("=" * 70)
            print("PERFORMING IN-PLACE INSERTION")
            print("=" * 70)
            print()
            
            inserter = InPlaceInserter(pe, analyzer)
            result = inserter.insert(hook_rva, payload, analysis)
            
            with open(output_path, 'wb') as f:
                f.write(result)
            
            print()
            print(f"✅ Successfully wrote patched file: {output_path}")
            print()
            print("⚠️  IMPORTANT: Test the patched file thoroughly before using in production!")
        elif not payload and (args.size > 0):
            # Analysis only mode (no payload, just size)
            print()
            print("To perform the actual insertion, provide payload (-n, -x, -c, or -b)")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())