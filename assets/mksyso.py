"""Собирает rsrc_windows_amd64.syso с иконкой из .ico (аналог утилиты rsrc)."""
import struct, sys

out_path = sys.argv[1]
icons, groups = [], []
for gi, ico_path in enumerate(sys.argv[2:]):
    ico = open(ico_path, 'rb').read()
    _, typ, count = struct.unpack_from('<HHH', ico, 0)
    grp = struct.pack('<HHH', 0, 1, count)
    for i in range(count):
        w, h, cc, res, planes, bpp, size, off = struct.unpack_from('<BBBBHHII', ico, 6 + 16 * i)
        icons.append(ico[off:off + size])
        grp += struct.pack('<BBBBHHIH', w, h, cc, 0, planes or 1, bpp or 32, size, len(icons))
    groups.append((gi + 1, grp))
# (type, [(id, data)])
types = [(3, [(i + 1, d) for i, d in enumerate(icons)]), (14, groups)]

def dirhdr(n):
    return struct.pack('<IIHHHH', 0, 0, 0, 0, 0, n)

# раскладка: корень, каталоги типов, каталоги языков, data entries, данные
root_size = 16 + 8 * len(types)
off = root_size
type_dir_off = []
for t, items in types:
    type_dir_off.append(off)
    off += 16 + 8 * len(items)
lang_dir_off = []
for t, items in types:
    lst = []
    for _ in items:
        lst.append(off)
        off += 16 + 8
    lang_dir_off.append(lst)
entry_off = []
for t, items in types:
    lst = []
    for _ in items:
        lst.append(off)
        off += 16
    entry_off.append(lst)
data_off = []
for t, items in types:
    lst = []
    for _, d in items:
        off = (off + 7) & ~7
        lst.append(off)
        off += len(d)
    data_off.append(lst)
total = (off + 7) & ~7

buf = bytearray(total)
buf[0:16] = dirhdr(len(types))
for k, (t, items) in enumerate(types):
    struct.pack_into('<II', buf, 16 + 8 * k, t, 0x80000000 | type_dir_off[k])
    base = type_dir_off[k]
    buf[base:base + 16] = dirhdr(len(items))
    for j, (rid, d) in enumerate(items):
        struct.pack_into('<II', buf, base + 16 + 8 * j, rid, 0x80000000 | lang_dir_off[k][j])
        lb = lang_dir_off[k][j]
        buf[lb:lb + 16] = dirhdr(1)
        struct.pack_into('<II', buf, lb + 16, 0x0409, entry_off[k][j])
        struct.pack_into('<IIII', buf, entry_off[k][j], data_off[k][j], len(d), 0, 0)
        buf[data_off[k][j]:data_off[k][j] + len(d)] = d

relocs = [e for lst in entry_off for e in lst]
hdr_size = 20 + 40
raw_ptr = hdr_size
reloc_ptr = raw_ptr + total
sym_ptr = reloc_ptr + 10 * len(relocs)

out = bytearray()
out += struct.pack('<HHIIIHH', 0x8664, 1, 0, sym_ptr, 1, 0, 0)
out += struct.pack('<8sIIIIIIHHI', b'.rsrc', 0, 0, total, raw_ptr, reloc_ptr, 0, len(relocs), 0, 0x40000040)
out += buf
for r in relocs:
    out += struct.pack('<IIH', r, 0, 3)  # IMAGE_REL_AMD64_ADDR32NB
out += struct.pack('<8sIhHBB', b'.rsrc', 0, 1, 0, 3, 0)
out += struct.pack('<I', 4)
open(out_path, 'wb').write(out)
print('ok', len(icons), 'images,', len(groups), 'groups,', len(out), 'bytes')
