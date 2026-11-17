package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// эталон: контрольная сумма корректного пакета, посчитанная заново по всему заголовку, = 0
func sumOK(b []byte, ihl int, proto byte) bool {
	if csum(b[:ihl], 0) != 0 {
		return false
	}
	var ps uint32
	for i := 12; i < 20; i += 2 {
		ps += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	l4 := b[ihl:]
	ps += uint32(proto) + uint32(len(l4))
	return csum(l4, ps) == 0
}

func TestPkt(t *testing.T) {
	x, d, pc := netip.MustParseAddr("192.168.0.50"), netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("192.168.0.166")
	u := buildUDP4(d, 3074, x, 50000, []byte("hello"))
	p, ok := parsePkt4(u)
	if !ok || p.src != d || p.dp != 50000 || string(p.payload()) != "hello" || !sumOK(u, 20, 17) {
		t.Fatal("udp")
	}
	// TCP SYN вручную
	tcp := make([]byte, 40)
	tcp[0], tcp[8], tcp[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(tcp[2:4], 40)
	copy(tcp[12:16], x.AsSlice())
	copy(tcp[16:20], d.AsSlice())
	binary.BigEndian.PutUint16(tcp[20:22], 51000)
	binary.BigEndian.PutUint16(tcp[22:24], 443)
	tcp[32] = 5 << 4
	tcp[33] = 0x02
	p, ok = parsePkt4(tcp)
	if !ok || p.tcpFlags() != 2 {
		t.Fatal("tcp parse")
	}
	p.setDst(pc, 10840)
	if !sumOK(tcp, 20, 6) || p.dst != pc || binary.BigEndian.Uint16(tcp[22:24]) != 10840 {
		t.Fatal("tcp rewrite")
	}
	p.setSrc(d, 443)
	if !sumOK(tcp, 20, 6) {
		t.Fatal("tcp rewrite2")
	}
}
