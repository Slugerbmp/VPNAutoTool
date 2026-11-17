package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeIO struct {
	mu  sync.Mutex
	out [][]byte
	dir []bool
}

func (f *fakeIO) Inject(b []byte, outbound bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out = append(f.out, append([]byte(nil), b...))
	f.dir = append(f.dir, outbound)
	return nil
}

func TestGatewayTCPNAT(t *testing.T) {
	pc, x, d := netip.MustParseAddr("192.168.0.166"), netip.MustParseAddr("192.168.0.50"), netip.MustParseAddr("20.30.40.50")
	io := &fakeIO{}
	g := newGateway(pc, io)
	g.cfg.Store(&gwConfig{On: true, Mode: "direct"})
	syn := make([]byte, 40)
	syn[0], syn[8], syn[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(syn[2:4], 40)
	copy(syn[12:16], x.AsSlice())
	copy(syn[16:20], d.AsSlice())
	binary.BigEndian.PutUint16(syn[20:22], 51000)
	binary.BigEndian.PutUint16(syn[22:24], 443)
	syn[32], syn[33] = 5<<4, 0x02
	if !g.onForward(syn) || len(io.out) != 1 || io.dir[0] {
		t.Fatal("syn not taken")
	}
	p, _ := parsePkt4(io.out[0])
	if p.dst != pc || p.dp != gwTCPPort || p.src != x {
		t.Fatal("bad rewrite", p.dst, p.dp)
	}
	// ответ приёмника
	rep := append([]byte(nil), io.out[0]...)
	rp, _ := parsePkt4(rep)
	rp.setSrc(pc, gwTCPPort)
	rp.setDst(x, 51000)
	if !g.onOutbound(rep) {
		t.Fatal("reply not rewritten")
	}
	rp, _ = parsePkt4(rep)
	if rp.src != d || rp.sp != 443 {
		t.Fatal("reply src", rp.src, rp.sp)
	}
	// LAN-назначение не трогаем
	lan := append([]byte(nil), syn...)
	copy(lan[16:20], netip.MustParseAddr("192.168.0.1").AsSlice())
	if g.onForward(lan) {
		t.Fatal("lan taken")
	}
}

// SOCKS5 UDP через настоящее ядро Xray → эхо-сервер.
func TestSocksUDPXray(t *testing.T) {
	if _, err := os.Stat(xrayBin()); err != nil {
		t.Skip()
	}
	echo, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer echo.Close()
	go func() {
		b := make([]byte, 2000)
		for {
			n, a, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(append([]byte("re:"), b[:n]...), a)
		}
	}()
	cfg := `{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":47999,"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],"outbounds":[{"protocol":"freedom"}]}`
	f := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(f, []byte(cfg), 0644)
	cmd := exec.Command(xrayBin(), "run", "-c", f)
	cmd.Start()
	defer cmd.Process.Kill()
	time.Sleep(700 * time.Millisecond)
	dst, _ := netip.ParseAddrPort(echo.LocalAddr().String())
	s, err := socksUDPDial(47999, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Send([]byte("ping"))
	b := make([]byte, 100)
	n, err := s.Recv(b)
	if err != nil || string(b[:n]) != "re:ping" {
		t.Fatal(err, string(b[:n]))
	}
	// HTTP CONNECT к ядру
	cfg2 := `{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":47998,"protocol":"http"}],"outbounds":[{"protocol":"freedom"}]}`
	f2 := filepath.Join(t.TempDir(), "c2.json")
	os.WriteFile(f2, []byte(cfg2), 0644)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { c, _ := ln.Accept(); c.Write([]byte("hi")); c.Close() }()
	cmd2 := exec.Command(xrayBin(), "run", "-c", f2)
	cmd2.Start()
	defer cmd2.Process.Kill()
	time.Sleep(700 * time.Millisecond)
	up, err := httpConnect(47998, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := make([]byte, 2)
	up.Read(r)
	if string(r) != "hi" {
		t.Fatal("connect data", string(r))
	}
}

func TestGatewayTCPConn(t *testing.T) {
	g := newGateway(netip.MustParseAddr("127.0.0.1"), &fakeIO{})
	g.cfg.Store(&gwConfig{On: true, Mode: "direct"})
	srv, _ := net.Listen("tcp4", "127.0.0.1:0")
	go func() {
		c, _ := srv.Accept()
		b := make([]byte, 5)
		c.Read(b)
		c.Write(append([]byte("ok:"), b...))
		c.Close()
	}()
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	go g.serveTCP(ln)
	cl := netip.MustParseAddrPort("127.0.0.1:47123")
	g.mu.Lock()
	g.tcp[cl] = &tcpEnt{dst: netip.MustParseAddrPort(srv.Addr().String()), seen: time.Now()}
	g.mu.Unlock()
	d := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(cl)}
	c, err := d.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello"))
	b := make([]byte, 20)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := c.Read(b)
	if string(b[:n]) != "ok:hello" {
		t.Fatalf("%q", b[:n])
	}
}
