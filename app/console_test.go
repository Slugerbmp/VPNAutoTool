package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSNIAndDNS(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: "rr3---sn-abc.googlevideo.com"})
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Handshake()
	}()
	if h := peekSNI(bufio.NewReaderSize(b, 16384)); h != "rr3---sn-abc.googlevideo.com" {
		t.Fatalf("sni %q", h)
	}
	a2, b2 := net.Pipe()
	go a2.Write([]byte("GET / HTTP/1.1\r\nHost: www.youtube.com:80\r\nUser-Agent: x\r\n\r\n"))
	if h := peekHTTPHost(bufio.NewReader(b2)); h != "www.youtube.com" {
		t.Fatalf("host %q", h)
	}
	m := map[string]bool{"googlevideo.com": true, "youtube.com": true}
	bypassList = []string{"lolka.app"}
	if !matchDomain(m, "rr3---sn-abc.googlevideo.com.") || matchDomain(m, "psn.playstation.net") || matchDomain(m, "notyoutube.com") {
		t.Fatal("match")
	}
	cons.ip, cons.domains = "192.168.137.1", m
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split("www.youtube.com", ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	r := dnsAnswer(q)
	if binary.BigEndian.Uint16(r[6:8]) != 1 || net.IP(r[len(r)-4:]).String() != "192.168.137.1" || r[0] != 0x12 {
		t.Fatalf("dns %x", r)
	}
	q[len(q)-3] = 28 // AAAA → пусто
	if r := dnsAnswer(q); binary.BigEndian.Uint16(r[6:8]) != 0 || r[3]&0x0f != 0 {
		t.Fatalf("aaaa %x", r)
	}
	cons.ip, cons.domains = "", nil
}

func TestXboxAuthRedirect(t *testing.T) {
	m := map[string]bool{}
	if !matchDomain(m, "xsts.auth.xboxlive.com") || !matchDomain(m, "user.auth.xboxlive.com.") || !matchDomain(m, "title.mgt.xboxlive.com") || matchDomain(m, "assets1.xboxlive.com") || matchDomain(m, "psn.playstation.net") {
		t.Fatal("xbox auth")
	}
}

func TestGeo(t *testing.T) {
	loc, w := parseTrace("fl=1\nip=1.2.3.4\nloc=nl\nwarp=on\n")
	if loc != "NL" || !w {
		t.Fatal(loc, w)
	}
	if !looksRussian("🇫🇲³🔄 Авто обход") || looksRussian("🇬🇧²⚡ Лондон") {
		t.Fatal("ru")
	}
	if !isGeoHost("XSTS.auth.xboxlive.com.") || !isGeoHost("login.live.com") || isGeoHost("tlu.dl.delivery.mp.microsoft.com") || isGeoHost("www.microsoft.com") {
		t.Fatal("geohost")
	}
}

func TestCIS(t *testing.T) {
	if flagCountry("🇧🇾 Минск") != "BY" || flagCountry("Лондон") != "" || !isCIS("by") || isCIS("DE") {
		t.Fatal("cis")
	}
}
