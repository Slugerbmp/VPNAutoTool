"""Склеивает два Mach-O (x86_64 + arm64) в универсальный файл (аналог lipo -create)."""
import struct, sys

out, amd, arm = sys.argv[1:4]
a, b = open(amd, 'rb').read(), open(arm, 'rb').read()
align = 1 << 14
off1 = align
off2 = (off1 + len(a) + align - 1) // align * align
hdr = struct.pack('>II', 0xcafebabe, 2)
hdr += struct.pack('>IIIII', 0x01000007, 3, off1, len(a), 14)  # x86_64
hdr += struct.pack('>IIIII', 0x0100000c, 0, off2, len(b), 14)  # arm64
buf = bytearray(off2 + len(b))
buf[:len(hdr)] = hdr
buf[off1:off1 + len(a)] = a
buf[off2:off2 + len(b)] = b
open(out, 'wb').write(buf)
