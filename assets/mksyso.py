"""Собирает rsrc_windows_amd64.syso: значки из .ico, сведения о файле (VERSIONINFO)
и манифест (asInvoker). Сведения о версии и манифест заметно снижают число ложных
срабатываний антивирусов на неподписанные программы.

  mksyso.py out.syso a.ico [b.ico ...] [--ver 1.2.3] [--file VPNAuto.exe] [--desc "..."]
"""
import struct, sys

args = sys.argv[1:]
opts = {}
pos = []
i = 0
while i < len(args):
    if args[i].startswith('--'):
        opts[args[i][2:]] = args[i + 1]
        i += 2
    else:
        pos.append(args[i])
        i += 1
out_path = pos[0]
icons, groups = [], []
for gi, ico_path in enumerate(pos[1:]):
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


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def block(key, value=b'', vtype=1, value_len=None, children=b''):
    k = (key + '\0').encode('utf-16-le')
    head_len = 6 + len(k)
    body = pad4(b'\0' * head_len)[head_len:]  # выравнивание после ключа
    data = value
    if data:
        data = pad4(data)
    raw = k + body + data + children
    vl = value_len if value_len is not None else (len(value) // 2 if vtype == 1 else len(value))
    return struct.pack('<HHH', 6 + len(raw), vl, vtype) + raw


if 'ver' in opts:
    v = [int(x) for x in (opts['ver'].split('.') + ['0', '0', '0'])[:4]]
    ms, ls = (v[0] << 16) | v[1], (v[2] << 16) | v[3]
    fixed = struct.pack('<13I', 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x00040004, 1, 0, 0, 0)
    name = opts.get('name', 'VPN Auto')
    strings = [('CompanyName', 'undr'), ('FileDescription', opts.get('desc', name)), ('FileVersion', opts['ver']),
               ('InternalName', opts.get('file', 'VPNAuto.exe').rsplit('.', 1)[0]), ('LegalCopyright', '© undr'),
               ('OriginalFilename', opts.get('file', 'VPNAuto.exe')), ('ProductName', name), ('ProductVersion', opts['ver'])]
    table = b''
    for k, val in strings:
        sv = (val + '\0').encode('utf-16-le')
        table += pad4(block(k, sv, 1, len(sv) // 2))
    st = pad4(block('040904B0', b'', 1, 0, table))
    sfi = pad4(block('StringFileInfo', b'', 1, 0, st))
    var = pad4(block('Translation', struct.pack('<HH', 0x0409, 0x04B0), 0, 4))
    vfi = pad4(block('VarFileInfo', b'', 1, 0, var))
    vs = block('VS_VERSION_INFO', fixed, 0, len(fixed), sfi + vfi)
    types.append((16, [(1, vs)]))
    manifest = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="undr.VPNAuto" version="%d.%d.%d.%d"/>
  <description>%s</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>
    <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
  </requestedPrivileges></security></trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>
    <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
  </application></compatibility>
</assembly>
''' % (v[0], v[1], v[2], v[3], name.encode())
    types.append((24, [(1, manifest)]))

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
