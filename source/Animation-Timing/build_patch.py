"""Adds import-backed visual-clock hooks to the verified widescreen executable."""
from pathlib import Path
import hashlib
import json
import struct

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parents[1]
BASE_SHA = '821891f2c769f3582293f656cc2db6909965ae69e8df894bfb57e79b31ef7c44'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def align(number, multiple):
    return (number + multiple - 1) // multiple * multiple


def build(source):
    if sha(source) != BASE_SHA:
        raise ValueError('Se requiere el ejecutable 16:9 de esta edicion, sin otros parches de ejecutable.')
    pe = struct.unpack_from('<I', source, 60)[0]
    optional = pe + 24
    count = struct.unpack_from('<H', source, pe + 6)[0]
    table = optional + struct.unpack_from('<H', source, pe + 20)[0]
    image_base = struct.unpack_from('<I', source, optional + 28)[0]
    section_alignment, file_alignment = struct.unpack_from('<II', source, optional + 32)
    sections = [struct.unpack_from('<IIII', source, table + i * 40 + 8) for i in range(count)]
    if image_base != 0x400000 or struct.unpack_from('<H', source, optional)[0] != 0x10b:
        raise ValueError('Formato PE inesperado.')
    if table + (count + 1) * 40 > min(raw for _, _, _, raw in sections):
        raise ValueError('No hay espacio para otra cabecera PE.')
    def offset(rva):
        for virtual_size, start, raw_size, raw in sections:
            if start <= rva < start + max(virtual_size, raw_size):
                return raw + rva - start
        raise ValueError('RVA fuera del archivo.')
    section_rva = align(max(start + max(vs, rs) for vs, start, rs, _ in sections), section_alignment)
    section_va = image_base + section_rva
    payload = bytearray()
    def append(data, boundary=1):
        start = align(len(payload), boundary)
        payload.extend(bytes(start - len(payload)))
        payload.extend(data)
        return start
    # Code is fixed-size and filled after the import table addresses are known.
    cursor_code = append(bytes(32), 16)
    marker_code = append(bytes(32), 16)
    import_rva, _ = struct.unpack_from('<II', source, optional + 104)
    original_imports = bytearray()
    position = offset(import_rva)
    while source[position:position + 20] != bytes(20):
        original_imports.extend(source[position:position + 20])
        position += 20
    import_table = append(bytes(len(original_imports) + 40), 4)
    dll_name = append(b'WBAnim.dll\0')
    cursor_name = append(b'\0\0WBAnimCursor\0', 2)
    marker_name = append(b'\0\0WBAnimMarker\0', 2)
    thunk_values = (section_rva + cursor_name, section_rva + marker_name, 0)
    lookup = append(struct.pack('<3I', *thunk_values), 4)
    iat = append(struct.pack('<3I', *thunk_values), 4)
    payload[import_table:import_table + len(original_imports)] = original_imports
    struct.pack_into('<5I', payload, import_table + len(original_imports),
                     section_rva + lookup, 0, 0, section_rva + dll_name, section_rva + iat)
    relocations = []
    # Save caller registers, forward old byte, and replace only saved CL with AL.
    code = bytearray(b'\x50\x52\x51\x0f\xb6\x86\x94\x01\x00\x00\x50\xff\x15')
    relocations.append(cursor_code + len(code))
    code.extend(struct.pack('<I', section_va + iat))
    code.extend(b'\x88\x04\x24\x59\x5a\x58\xc3')
    payload[cursor_code:cursor_code + len(code)] = code
    cursor_size = len(code)
    code = bytearray(b'\x51\x52\xff\x15')
    relocations.append(marker_code + len(code))
    code.extend(struct.pack('<I', section_va + iat + 4))
    code.extend(b'\x5a\x59\x83\xf8\xff\x74\x01\xc3\xe9')
    code.extend(struct.pack('<i', 0x4708b0 - (section_va + marker_code + len(code) + 4)))
    payload[marker_code:marker_code + len(code)] = code
    marker_size = len(code)
    # Append original relocation blocks, followed by HIGHLOW entries for the hooks.
    reloc_rva, reloc_size = struct.unpack_from('<II', source, optional + 136)
    reloc_table = append(source[offset(reloc_rva):offset(reloc_rva) + reloc_size], 4)
    entries = [0x3000 | value for value in relocations]
    if len(entries) % 2:
        entries.append(0)
    append(struct.pack('<II', section_rva, 8 + len(entries) * 2) + struct.pack('<' + 'H' * len(entries), *entries))
    new_reloc_size = len(payload) - reloc_table
    output = bytearray(source)
    patches = []
    signatures = [
        (0x47b77c, bytes.fromhex('8a 8e 94 01 00 00 fe c1'), section_va + cursor_code),
        (0x446600, bytes.fromhex('e8 ab a2 02 00'), section_va + marker_code),
        (0x47ca02, bytes.fromhex('e8 a9 3e ff ff'), section_va + marker_code),
    ]
    for address, before, destination in signatures:
        at = offset(address - image_base)
        if source[at:at + len(before)] != before:
            raise ValueError('Firma de instrucciones inesperada: ' + hex(address))
        after = b'\xe8' + struct.pack('<i', destination - address - 5) + b'\x90' * (len(before) - 5)
        output[at:at + len(before)] = after
        patches.append({'va': address, 'file_offset': at, 'before': before.hex(), 'after': after.hex()})
    raw_offset = align(len(output), file_alignment)
    raw_size = align(len(payload), file_alignment)
    output.extend(bytes(raw_offset - len(output)))
    output.extend(payload + bytes(raw_size - len(payload)))
    # Writable IAT; no executable data from resources is moved or replaced.
    struct.pack_into('<8sIIIIIIHHI', output, table + count * 40, b'.wbanim\0', len(payload),
                     section_rva, raw_size, raw_offset, 0, 0, 0, 0, 0xe0000060)
    struct.pack_into('<H', output, pe + 6, count + 1)
    struct.pack_into('<I', output, optional + 56, align(section_rva + len(payload), section_alignment))
    struct.pack_into('<I', output, optional + 4, struct.unpack_from('<I', source, optional + 4)[0] + 64)
    struct.pack_into('<I', output, optional + 8, struct.unpack_from('<I', source, optional + 8)[0] + raw_size - 64)
    struct.pack_into('<II', output, optional + 104, section_rva + import_table, len(original_imports) + 40)
    struct.pack_into('<II', output, optional + 136, section_rva + reloc_table, new_reloc_size)
    # Preserve the original IAT directory. The added descriptor identifies its new
    # writable FirstThunk. Do not span executable hook pages with the IAT range:
    # the Windows loader can protect that range as data after resolving imports.
    struct.pack_into('<I', output, optional + 64, 0)
    details = {'new_section_rva': section_rva, 'raw_offset': raw_offset, 'payload_size': len(payload),
               'cursor_hook_va': section_va + cursor_code, 'marker_hook_va': section_va + marker_code,
               'cursor_hook_size': cursor_size, 'marker_hook_size': marker_size,
               'iat_rva': section_rva + iat, 'relocation_operands': relocations,
               'original_import_descriptor_count': len(original_imports) // 20,
               'patches': patches}
    return bytes(output), details


if __name__ == '__main__':
    prepared = PACKAGE / 'prepared'
    source = (ROOT / 'WARBREED.EXE').read_bytes()
    executable, code = build(source)
    (prepared / 'WARBREED.EXE').write_bytes(executable)
    for path in [prepared / 'WBAnim.dll']:
        pe = struct.unpack_from('<I', path.read_bytes(), 60)[0]
        if struct.unpack_from('<H', path.read_bytes(), pe + 4)[0] != 0x14c:
            raise ValueError('El runtime debe ser x86.')
    report = {'base_sha256': BASE_SHA, 'installed_sha256': sha(executable),
              'dll_sha256': sha((prepared / 'WBAnim.dll').read_bytes()),
              'default_cursor_fps': 12, 'default_marker_fps': 10, 'code': code}
    (PACKAGE / 'build-manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
