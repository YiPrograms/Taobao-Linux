#!/usr/bin/env python3
"""Repair objconv 2.57's ELF64 RELA addends and preserve Mach-O weak defs.

Only use on FRESH objconv output, never on arbitrary ELF or linked binaries.
objconv leaves its computed addends in section bytes while emitting RELA
records with zero addends. ELF64 linkers ignore those inline bytes.
"""

import struct
import sys
from pathlib import Path


def weak_definitions(macho):
    if macho[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("expected little-endian 64-bit Mach-O")
    count = struct.unpack_from("<I", macho, 16)[0]
    offset = 32
    weak = set()
    for _ in range(count):
        command, size = struct.unpack_from("<II", macho, offset)
        if command == 2:  # LC_SYMTAB
            symoff, nsyms, stroff, _ = struct.unpack_from("<IIII", macho, offset + 8)
            for index in range(nsyms):
                nameoff, kind, _, flags, _ = struct.unpack_from(
                    "<IBBHQ", macho, symoff + 16 * index
                )
                if kind & 1 and flags & 0x80:  # N_EXT, N_WEAK_DEF
                    start = stroff + nameoff
                    name = macho[start : macho.index(0, start)].decode()
                    weak.add(name.removeprefix("_"))
        offset += size
    return weak


def normalize(original, converted):
    weak = weak_definitions(Path(original).read_bytes())
    destination = Path(converted)
    data = bytearray(destination.read_bytes())
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 62:
        raise ValueError("expected little-endian x86-64 ELF")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count = struct.unpack_from("<HH", data, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsize) for i in range(count)]
    repairs = weak_count = 0
    for section in sections:
        if section[1] == 4:  # SHT_RELA
            target = sections[section[7]]
            if target[1] == 8:
                raise ValueError("cannot relocate inline bytes in NOBITS")
            for offset in range(section[4], section[4] + section[5], section[9]):
                address, info, addend = struct.unpack_from("<QQq", data, offset)
                if addend:
                    raise ValueError(
                        "nonzero RELA addend: already repaired or unsupported converter"
                    )
                kind = info & 0xFFFFFFFF
                fmt = {1: "<q", 2: "<i", 10: "<I", 11: "<i", 24: "<q"}.get(kind)
                if fmt is None:
                    raise ValueError(f"unsupported relocation {kind}")
                if address + struct.calcsize(fmt) > target[5]:
                    raise ValueError("relocation exceeds target section")
                location = target[4] + address
                value = struct.unpack_from(fmt, data, location)[0]
                struct.pack_into("<q", data, offset + 16, value)
                struct.pack_into(fmt, data, location, 0)
                repairs += 1
        elif section[1] == 2:  # SHT_SYMTAB
            strings = sections[section[6]]
            for offset in range(section[4], section[4] + section[5], section[9]):
                nameoff = struct.unpack_from("<I", data, offset)[0]
                start = strings[4] + nameoff
                name = data[start : data.index(0, start)].decode()
                if name in weak:
                    data[offset + 4] = 0x20 | (data[offset + 4] & 0xF)  # STB_WEAK
                    weak_count += 1
    destination.write_bytes(data)
    return repairs, weak_count


if __name__ == "__main__":
    print(normalize(*sys.argv[1:]))
