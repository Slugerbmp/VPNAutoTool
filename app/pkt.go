package main

// Разбор и сборка IPv4/TCP/UDP-пакетов для режима шлюза (подмена адресов, контрольные суммы).

import (
	"encoding/binary"
	"net/netip"
)

type pkt4 struct {
	b        []byte
	ihl      int
	proto    byte
	src, dst netip.Addr
	sp, dp   uint16
}

func parsePkt4(b []byte) (p pkt4, ok bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	tot := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || tot > len(b) || tot < ihl+8 {
		return
	}
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 { // фрагменты не трогаем
		return
	}
	p = pkt4{b: b[:tot], ihl: ihl, proto: b[9]}
	p.src = netip.AddrFrom4([4]byte(b[12:16]))
	p.dst = netip.AddrFrom4([4]byte(b[16:20]))
	if p.proto != 6 && p.proto != 17 {
		return p, false
	}
	if p.proto == 6 && tot < ihl+20 {
		return p, false
	}
	p.sp = binary.BigEndian.Uint16(b[ihl : ihl+2])
	p.dp = binary.BigEndian.Uint16(b[ihl+2 : ihl+4])
	return p, true
}

func (p *pkt4) tcpFlags() byte {
	if p.proto != 6 {
		return 0
	}
	return p.b[p.ihl+13]
}

func (p *pkt4) payload() []byte {
	if p.proto == 17 {
		return p.b[p.ihl+8:]
	}
	off := p.ihl + int(p.b[p.ihl+12]>>4)*4
	if off > len(p.b) {
		return nil
	}
	return p.b[off:]
}

func (p *pkt4) setSrc(a netip.Addr, port uint16) {
	x := a.As4()
	copy(p.b[12:16], x[:])
	binary.BigEndian.PutUint16(p.b[p.ihl:p.ihl+2], port)
	p.src, p.sp = a, port
	p.fixSums()
}

func (p *pkt4) setDst(a netip.Addr, port uint16) {
	x := a.As4()
	copy(p.b[16:20], x[:])
	binary.BigEndian.PutUint16(p.b[p.ihl+2:p.ihl+4], port)
	p.dst, p.dp = a, port
	p.fixSums()
}

func csum(data []byte, init uint32) uint16 {
	s := init
	for i := 0; i+1 < len(data); i += 2 {
		s += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		s += uint32(data[len(data)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// Пересчитать контрольные суммы IP и TCP/UDP.
func (p *pkt4) fixSums() {
	b := p.b
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:12], csum(b[:p.ihl], 0))
	l4 := b[p.ihl:]
	var ps uint32
	for i := 12; i < 20; i += 2 {
		ps += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	ps += uint32(p.proto) + uint32(len(l4))
	switch p.proto {
	case 6:
		l4[16], l4[17] = 0, 0
		binary.BigEndian.PutUint16(l4[16:18], csum(l4, ps))
	case 17:
		l4[6], l4[7] = 0, 0
		c := csum(l4, ps)
		if c == 0 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(l4[6:8], c)
	}
}

var ipID uint16

// Собрать UDP-пакет (ответ приставке от имени исходного сервера).
func buildUDP4(src netip.Addr, sp uint16, dst netip.Addr, dp uint16, data []byte) []byte {
	b := make([]byte, 28+len(data))
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	ipID++
	binary.BigEndian.PutUint16(b[4:6], ipID)
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:22], sp)
	binary.BigEndian.PutUint16(b[22:24], dp)
	binary.BigEndian.PutUint16(b[24:26], uint16(8+len(data)))
	copy(b[28:], data)
	p := pkt4{b: b, ihl: 20, proto: 17, src: src, dst: dst, sp: sp, dp: dp}
	p.fixSums()
	return b
}
