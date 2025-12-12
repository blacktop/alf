"Uses a pure-Python Mach-O parser for speed, falling back to system tools if needed."

from __future__ import annotations

import re
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# --- Pure Python Mach-O Parser ---

# Mach-O Magics
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

# CPU Types
CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = 0x1000007
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x100000C

# Load Command Types
LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_RPATH = 0x8000001C
LC_CODE_SIGNATURE = 0x1D
LC_MAIN = 0x80000028
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F


@dataclass
class MachOHeader:
    magic: int
    cputype: int
    cpusubtype: int
    filetype: int
    ncmds: int
    sizeofcmds: int
    flags: int
    reserved: int = 0


@dataclass
class Section:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int
    align: int
    reloff: int
    nreloc: int
    flags: int
    reserved1: int
    reserved2: int = 0
    reserved3: int = 0


@dataclass
class Segment:
    segname: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    nsects: int
    flags: int
    sections: list[Section]


@dataclass
class Symbol:
    name: str
    type: int
    sect: int
    desc: int
    value: int


class MachOParser:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.header: MachOHeader | None = None
        self.load_commands: list[tuple[int, int, bytes]] = []  # (cmd, cmdsize, data)
        self.segments: list[Segment] = []
        self.slice_offset = 0
        self.endian = "<"
        self.is_64 = True
        self._f: BinaryIO | None = None

        try:
            with self.path.open("rb") as f:
                self._f = f
                self._parse()
        finally:
            self._f = None

    def _read_struct(self, fmt: str, offset: int = -1) -> tuple:
        if offset != -1:
            self._f.seek(offset)
        size = struct.calcsize(fmt)
        data = self._f.read(size)
        return struct.unpack(fmt, data)

    def _parse(self):
        # Check Magic
        magic_data = self._read_struct(">I", 0)
        magic = magic_data[0]

        if magic in (FAT_MAGIC, FAT_CIGAM):
            self._handle_fat(magic == FAT_CIGAM)

        # Read Header at slice_offset
        self._f.seek(self.slice_offset)
        magic_data = self._f.read(4)
        if len(magic_data) < 4:
            raise ValueError("Invalid Mach-O file")

        magic = struct.unpack("<I", magic_data)[0]
        if magic == MH_MAGIC_64:
            self.endian, self.is_64 = "<", True
        elif magic == MH_CIGAM_64:
            self.endian, self.is_64 = ">", True
        elif magic == MH_MAGIC:
            self.endian, self.is_64 = "<", False
        elif magic == MH_CIGAM:
            self.endian, self.is_64 = ">", False
        else:
            raise ValueError(f"Unknown magic: {hex(magic)}")

        # Parse Mach-Header
        if self.is_64:
            # magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
            fmt = f"{self.endian}IiiIIIII"
            fields = self._read_struct(fmt, self.slice_offset)
            self.header = MachOHeader(*fields)
        else:
            # magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
            fmt = f"{self.endian}IiiIIII"
            fields = self._read_struct(fmt, self.slice_offset)
            self.header = MachOHeader(*fields, reserved=0)

        # Parse Load Commands
        cursor = self._f.tell()
        for _ in range(self.header.ncmds):
            cmd, cmdsize = self._read_struct(f"{self.endian}II", cursor)
            # Read full command data including header
            self._f.seek(cursor)
            data = self._f.read(cmdsize)
            self.load_commands.append((cmd, cmdsize, data))

            # Parse Segments immediately
            if cmd == LC_SEGMENT_64:
                self._parse_segment_64(data)
            elif cmd == LC_SEGMENT:
                self._parse_segment_32(data)

            cursor += cmdsize

    def _handle_fat(self, is_cigam: bool):
        # Always big-endian headers
        nfat = self._read_struct(">I", 4)[0]
        # Prefer arm64e -> arm64 -> x86_64
        best_offset = 0
        best_prio = -1

        cursor = 8
        for _ in range(nfat):
            cputype, cpusubtype, offset, size, align = self._read_struct(">iiIII", cursor)
            prio = 0
            if cputype == CPU_TYPE_ARM64:
                prio = 3
                if cpusubtype == 0x80000002:  # arm64e
                    prio = 4
            elif cputype == CPU_TYPE_X86_64:
                prio = 2
            elif cputype == CPU_TYPE_ARM:
                prio = 1

            if prio > best_prio:
                best_prio = prio
                best_offset = offset

            cursor += 20

        if best_offset:
            self.slice_offset = best_offset

    def _decode_str(self, b: bytes) -> str:
        return b.split(b"\x00")[0].decode("utf-8", errors="ignore")

    def _parse_segment_64(self, data: bytes):
        # segname(16), vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags
        fmt = f"{self.endian}16sQQQQiiII"
        # Skip cmd(4)+cmdsize(4) = 8
        fields = struct.unpack(fmt, data[8:72])
        segname = self._decode_str(fields[0])
        nsects = fields[7]

        sections = []
        sect_offset = 72
        for _ in range(nsects):
            # sectname(16), segname(16), addr, size, offset, align, reloff,
            # nreloc, flags, reserved1, reserved2, reserved3
            s_fmt = f"{self.endian}16s16sQQIIIIIIII"
            s_data = data[sect_offset : sect_offset + 80]
            s_fields = struct.unpack(s_fmt, s_data)
            sections.append(
                Section(
                    sectname=self._decode_str(s_fields[0]),
                    segname=self._decode_str(s_fields[1]),
                    addr=s_fields[2],
                    size=s_fields[3],
                    offset=s_fields[4],
                    align=s_fields[5],
                    reloff=s_fields[6],
                    nreloc=s_fields[7],
                    flags=s_fields[8],
                    reserved1=s_fields[9],
                    reserved2=s_fields[10],
                    reserved3=s_fields[11],
                )
            )
            sect_offset += 80

        self.segments.append(
            Segment(
                segname,
                fields[1],
                fields[2],
                fields[3],
                fields[4],
                fields[5],
                fields[6],
                fields[7],
                fields[8],
                sections,
            )
        )

    def _parse_segment_32(self, data: bytes):
        # segname(16), vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags
        fmt = f"{self.endian}16sIIIIiiII"
        fields = struct.unpack(fmt, data[8:56])
        segname = self._decode_str(fields[0])
        nsects = fields[7]

        sections = []
        sect_offset = 56
        for _ in range(nsects):
            # sectname(16), segname(16), addr, size, offset, align, reloff, nreloc, flags, reserved1, reserved2
            s_fmt = f"{self.endian}16s16sIIIIIIIII"
            s_data = data[sect_offset : sect_offset + 68]
            s_fields = struct.unpack(s_fmt, s_data)
            sections.append(
                Section(
                    sectname=self._decode_str(s_fields[0]),
                    segname=self._decode_str(s_fields[1]),
                    addr=s_fields[2],
                    size=s_fields[3],
                    offset=s_fields[4],
                    align=s_fields[5],
                    reloff=s_fields[6],
                    nreloc=s_fields[7],
                    flags=s_fields[8],
                    reserved1=s_fields[9],
                    reserved2=s_fields[10],
                )
            )
            sect_offset += 68

        self.segments.append(
            Segment(
                segname,
                fields[1],
                fields[2],
                fields[3],
                fields[4],
                fields[5],
                fields[6],
                fields[7],
                fields[8],
                sections,
            )
        )

    # --- Public API ---

    def get_load_commands_summary(self) -> list[str]:
        summary = []
        for cmd, cmdsize, data in self.load_commands:
            name = f"CMD_{hex(cmd)}"
            if cmd == LC_SEGMENT_64:
                name = "LC_SEGMENT_64"
            elif cmd == LC_SEGMENT:
                name = "LC_SEGMENT"
            elif cmd == LC_LOAD_DYLIB:
                name = "LC_LOAD_DYLIB"
            elif cmd == LC_ID_DYLIB:
                name = "LC_ID_DYLIB"
            elif cmd == LC_UUID:
                name = "LC_UUID"
            elif cmd == LC_CODE_SIGNATURE:
                name = "LC_CODE_SIGNATURE"
            elif cmd == LC_MAIN:
                name = "LC_MAIN"
            elif cmd == LC_SYMTAB:
                name = "LC_SYMTAB"

            info = ""
            if cmd in (LC_SEGMENT, LC_SEGMENT_64):
                # extract segname
                segname = self._decode_str(data[8:24])
                info = f"name={segname}"
            elif cmd in (LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                offset = struct.unpack(f"{self.endian}I", data[8:12])[0]
                if offset < len(data):
                    path = self._decode_str(data[offset:])
                    info = f"path={path}"

            summary.append(f"{name:<20} size={cmdsize:<5} {info}")
        return summary

    def get_dylibs(self) -> list[str]:
        libs = []
        for cmd, _, data in self.load_commands:
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                # offset to name is at +8
                offset = struct.unpack(f"{self.endian}I", data[8:12])[0]
                libs.append(self._decode_str(data[offset:]))
        return libs

    def get_rpaths(self) -> list[str]:
        rpaths = []
        for cmd, _, data in self.load_commands:
            if cmd == LC_RPATH:
                offset = struct.unpack(f"{self.endian}I", data[8:12])[0]
                rpaths.append(self._decode_str(data[offset:]))
        return rpaths

    def get_entitlements(self) -> str | None:
        for cmd, _, data in self.load_commands:
            if cmd == LC_CODE_SIGNATURE:
                off, size = struct.unpack(f"{self.endian}II", data[8:16])
                # Read blob
                with self.path.open("rb") as f:
                    f.seek(self.slice_offset + off)
                    blob = f.read(size)
                    # Simple heuristic
                    start = blob.find(b"<?xml")
                    if start != -1:
                        end = blob.find(b"</plist>")
                        if end != -1:
                            return blob[start : end + 8].decode("utf-8", errors="ignore")
        return None

    def get_section_data(self, segname: str, sectname: str) -> bytes | None:
        for seg in self.segments:
            if segname and seg.segname != segname:
                continue
            for sect in seg.sections:
                if sect.sectname == sectname:
                    with self.path.open("rb") as f:
                        f.seek(self.slice_offset + sect.offset)
                        return f.read(sect.size)
        return None

    def get_sections_summary(self) -> list[str]:
        summary = []
        for seg in self.segments:
            summary.append(f"Segment: {seg.segname} (vmaddr={hex(seg.vmaddr)})")
            for sect in seg.sections:
                summary.append(f"  Section: {sect.sectname:<16} addr={hex(sect.addr):<18} size={hex(sect.size)}")
        return summary

    def get_objc_class_names(self) -> list[str]:
        # Parse __TEXT,__objc_classname (or __objc_methname in newer runtimes)
        # This gives string names. Linking them to class structs requires more parsing.
        # But dumping just names is useful.
        data = self.get_section_data("__TEXT", "__objc_classname")
        if not data:
            # Maybe __objc_methname?
            data = self.get_section_data("__TEXT", "__objc_methname")

        if not data:
            return []

        return [s for s in data.decode("utf-8", errors="ignore").split("\x00") if s]

    def get_min_version(self) -> str | None:
        # LC_VERSION_MIN_MACOSX etc or LC_BUILD_VERSION
        for cmd, _, data in self.load_commands:
            if cmd == 0x24:  # LC_VERSION_MIN_MACOSX
                v = struct.unpack(f"{self.endian}I", data[8:12])[0]
                return f"{(v >> 16) & 0xFFFF}.{(v >> 8) & 0xFF}.{v & 0xFF}"
            elif cmd == 0x32:  # LC_BUILD_VERSION
                v = struct.unpack(f"{self.endian}I", data[12:16])[0]  # minos is at +12
                return f"{(v >> 16) & 0xFFFF}.{(v >> 8) & 0xFF}.{v & 0xFF}"
        return None

    def get_symbols(self) -> list[Symbol]:
        symbols = []
        symtab_cmd = None
        for cmd, _, data in self.load_commands:
            if cmd == LC_SYMTAB:
                # symoff(4), nsyms(4), stroff(4), strsize(4)
                symtab_cmd = struct.unpack(f"{self.endian}IIII", data[8:24])
                break

        if not symtab_cmd:
            return []

        symoff, nsyms, stroff, strsize = symtab_cmd

        with self.path.open("rb") as f:
            # Read String Table
            f.seek(self.slice_offset + stroff)
            strtab = f.read(strsize)

            # Read Nlist
            f.seek(self.slice_offset + symoff)

            # n_list_64: strx(4), type(1), sect(1), desc(2), value(8) = 16 bytes
            # n_list_32: strx(4), type(1), sect(1), desc(2), value(4) = 12 bytes

            entry_size = 16 if self.is_64 else 12
            fmt = f"{self.endian}IBBHQ" if self.is_64 else f"{self.endian}IBBHI"

            # Chunked reading to avoid OOM on huge binaries
            CHUNK_SIZE = 10000
            for i in range(0, nsyms, CHUNK_SIZE):
                chunk_count = min(CHUNK_SIZE, nsyms - i)
                blob = f.read(chunk_count * entry_size)

                for j in range(chunk_count):
                    off = j * entry_size
                    fields = struct.unpack_from(fmt, blob, off)
                    n_strx = fields[0]
                    # decode name
                    name = ""
                    if n_strx < len(strtab):
                        # Find null terminator
                        end = strtab.find(b"\x00", n_strx)
                        if end != -1:
                            name = strtab[n_strx:end].decode("utf-8", errors="ignore")

                    symbols.append(Symbol(name, fields[1], fields[2], fields[3], fields[4]))

        return symbols


# --- Tool Helpers ---


def _run_local_cmd(args: list[str], timeout: float = 10.0) -> str:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        return f"Error: command '{args[0]}' not found"
    except subprocess.TimeoutExpired:
        return f"Error: command '{args[0]}' timed out after {timeout:.1f}s"
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode != 0:
        msg = err or out or f"exit={proc.returncode}"
        return f"Error running {' '.join(args)}: {msg}"
    return "\n".join([s for s in (out, err) if s]).strip()


def _run_local_cmd_with_input(args: list[str], input_text: str, timeout: float = 10.0) -> str:
    try:
        proc = subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        return f"Error: command '{args[0]}' not found"
    except subprocess.TimeoutExpired:
        return f"Error: command '{args[0]}' timed out after {timeout:.1f}s"
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode != 0:
        msg = err or out or f"exit={proc.returncode}"
        return f"Error running {' '.join(args)}: {msg}"
    return "\n".join([s for s in (out, err) if s]).strip()


def _xcrun_if_needed(args: list[str], timeout: float = 10.0) -> str:
    out = _run_local_cmd(args, timeout=timeout)
    if out.startswith("Error: command") or out.startswith("Error running"):
        return _run_local_cmd(["xcrun"] + args, timeout=timeout)
    return out


def macho_objc_segment(binary_path: str, max_results: int = 200) -> str:
    # This usually means dumping the __DATA,__objc_* sections
    # otool -ov does this well. Our parser can dump sections but not format them as structs yet.
    return _xcrun_if_needed(["otool", "-ov", binary_path], timeout=20.0)


def swift_demangle(symbols: str | list[str]) -> str:
    input_text = "\n".join(symbols) if isinstance(symbols, list) else str(symbols)
    # Swift demangle is hard to do in pure python without a huge library.
    # Keep using swift-demangle tool.
    out = _run_local_cmd_with_input(["swift-demangle"], input_text, timeout=8.0)
    if out.startswith("Error: command"):
        out = _run_local_cmd_with_input(["xcrun", "swift-demangle"], input_text, timeout=8.0)
    return out


def macho_swift_symbols(binary_path: str, demangle: bool = True, max_results: int = 200) -> str:
    try:
        p = MachOParser(binary_path)
        symbols = p.get_symbols()
    except Exception as e:
        return f"Error parsing Mach-O: {e}"

    mangled: list[str] = []
    # Regex for Swift symbols (standard _? $s... or old _T...)
    rx = re.compile(r"^(_?\$s[A-Za-z0-9_.$]+|_T[A-Za-z0-9_.$]+)")

    for s in symbols:
        if s.name and rx.match(s.name):
            mangled.append(s.name)

    uniq = sorted(set(mangled))
    if not uniq:
        return "No Swift symbols found."

    if max_results and max_results > 0:
        uniq = uniq[:max_results]

    if not demangle:
        return "\n".join(uniq)

    dm = swift_demangle(uniq)
    return dm
