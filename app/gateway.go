package main

// Режим шлюза для приставок (Xbox, PlayStation): на приставке вручную указывается
// компьютер как основной шлюз. Пакеты приставки, которые компьютер должен переслать
// в интернет, перехватываются (WinDivert, уровень пересылки) и отдаются нашим
// прокси: TCP — через локальный приёмник с подменой адресов, UDP — напрямую из пакета.
// Наружу трафик идёт с компьютера: через VPN-сервер (режим VPN) или напрямую —
// тогда на него действуют запрет и WARP. Вход в Xbox — всегда через зарубежный выход.
// Если процесс шлюза упадёт, пересылка Windows остаётся включённой и приставка
// просто выходит в интернет напрямую.

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const gwTCPPort = 10840

type gwConfig struct {
	On       bool     `json:"on"`
	PC       string   `json:"pc"`
	IfIdx    int      `json:"ifIdx"`
	Mode     string   `json:"mode"`     // "vpn" — через VPN; "direct" — через компьютер (запрет/WARP)
	HTTP     []int    `json:"http"`     // HTTP-входы ядра (по порядку предпочтения)
	Socks    []int    `json:"socks"`    // SOCKS5-входы ядра
	GeoHTTP  []int    `json:"geoHttp"`  // зарубежные серверы для входа Xbox
	GeoSocks []int    `json:"geoSocks"` //
	Bypass   []string `json:"bypass"`
	GamesDir bool     `json:"gamesDirect"` // игровой UDP — напрямую (меньше пинг)
	TS       int64    `json:"ts"`
}

type gwState struct {
	PID     int    `json:"pid"`
	TCP     int64  `json:"tcp"`
	UDP     int64  `json:"udp"`
	Flows   int    `json:"flows"`
	Clients string `json:"clients"`
	Err     string `json:"err"`
	TS      int64  `json:"ts"`
}

func gwConfigPath() string { return filepath.Join(dataDir, "gateway.json") }
func gwStatePath() string  { return filepath.Join(dataDir, "gateway-state.json") }

// Ввод-вывод пакетов (WinDivert на Windows, заглушка в тестах).
type pktIO interface {
	Inject(b []byte, outbound bool) error
}

type tcpEnt struct {
	dst  netip.AddrPort
	seen time.Time
}

type udpFlow struct {
	client, dst netip.AddrPort
	up          udpUpstream
	seen        atomic.Int64
}

type udpUpstream interface {
	Send(b []byte) error
	Recv(buf []byte) (int, error)
	Close() error
}

type gateway struct {
	cfg     atomic.Pointer[gwConfig]
	pc      netip.Addr
	io      pktIO
	mu      sync.Mutex
	tcp     map[netip.AddrPort]*tcpEnt
	udp     map[string]*udpFlow
	clients map[netip.Addr]time.Time
	nTCP    atomic.Int64
	nUDP    atomic.Int64
}

func newGateway(pc netip.Addr, io pktIO) *gateway {
	return &gateway{pc: pc, io: io, tcp: map[netip.AddrPort]*tcpEnt{}, udp: map[string]*udpFlow{}, clients: map[netip.Addr]time.Time{}}
}

func isPrivate4(a netip.Addr) bool {
	b := a.As4()
	return b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1]&0xf0 == 16) || (b[0] == 192 && b[1] == 168) ||
		(b[0] == 169 && b[1] == 254) || b[0] >= 224 || b[0] == 0 || (b[0] == 100 && b[1]&0xc0 == 64)
}

// Пакет приставки, который Windows собиралась переслать в интернет.
// true — забрали себе; false — пусть идёт дальше как есть.
func (g *gateway) onForward(b []byte) bool {
	p, ok := parsePkt4(b)
	if !ok || isPrivate4(p.dst) || p.src == g.pc {
		return false
	}
	c := g.cfg.Load()
	if c == nil || !c.On {
		return false
	}
	now := time.Now()
	g.mu.Lock()
	g.clients[p.src] = now
	g.mu.Unlock()
	cl := netip.AddrPortFrom(p.src, p.sp)
	dst := netip.AddrPortFrom(p.dst, p.dp)
	switch p.proto {
	case 6:
		g.mu.Lock()
		e := g.tcp[cl]
		if p.tcpFlags()&0x12 == 0x02 { // SYN — новое соединение
			e = &tcpEnt{dst: dst}
			g.tcp[cl] = e
		}
		if e == nil || e.dst != dst {
			g.mu.Unlock()
			return false // соединение началось до включения шлюза
		}
		e.seen = now
		g.mu.Unlock()
		p.setDst(g.pc, gwTCPPort)
		g.io.Inject(p.b, false) // как будто пришло компьютеру
		return true
	case 17:
		if c.GamesDir && !gwUDPImportant(p.dp) {
			return false // игры по UDP — напрямую через роутер
		}
		payload := append([]byte(nil), p.payload()...)
		key := cl.String() + ">" + dst.String()
		g.mu.Lock()
		f := g.udp[key]
		g.mu.Unlock()
		if f == nil {
			up, err := g.udpDial(c, dst)
			if err != nil {
				return true // молча теряем: UDP переживёт
			}
			f = &udpFlow{client: cl, dst: dst, up: up}
			g.mu.Lock()
			if old := g.udp[key]; old != nil {
				g.mu.Unlock()
				up.Close()
				f = old
			} else {
				g.udp[key] = f
				g.mu.Unlock()
				go g.udpReader(key, f)
			}
		}
		f.seen.Store(now.Unix())
		f.up.Send(payload)
		g.nUDP.Add(int64(len(payload)))
		return true
	}
	return false
}

// Голос Discord (50000–65535) и DNS/QUIC везём через шлюз даже при «играх напрямую».
func gwUDPImportant(port uint16) bool {
	return port >= 50000 || port == 53 || port == 443
}

// Ответ нашего TCP-приёмника приставке: возвращаем адрес исходного сервера.
func (g *gateway) onOutbound(b []byte) bool {
	p, ok := parsePkt4(b)
	if !ok || p.proto != 6 || p.src != g.pc || p.sp != gwTCPPort {
		return false
	}
	g.mu.Lock()
	e := g.tcp[netip.AddrPortFrom(p.dst, p.dp)]
	if e != nil {
		e.seen = time.Now()
	}
	g.mu.Unlock()
	if e == nil {
		return false
	}
	p.setSrc(e.dst.Addr(), e.dst.Port())
	return true
}

func (g *gateway) udpReader(key string, f *udpFlow) {
	buf := make([]byte, 65535)
	for {
		n, err := f.up.Recv(buf)
		if err != nil {
			break
		}
		f.seen.Store(time.Now().Unix())
		g.nUDP.Add(int64(n))
		g.io.Inject(buildUDP4(f.dst.Addr(), f.dst.Port(), f.client.Addr(), f.client.Port(), buf[:n]), true)
	}
	g.mu.Lock()
	if g.udp[key] == f {
		delete(g.udp, key)
	}
	g.mu.Unlock()
	f.up.Close()
}

// Чистка устаревших записей.
func (g *gateway) janitor() {
	for {
		time.Sleep(30 * time.Second)
		now := time.Now()
		g.mu.Lock()
		for k, e := range g.tcp {
			if now.Sub(e.seen) > 15*time.Minute {
				delete(g.tcp, k)
			}
		}
		var dead []*udpFlow
		for k, f := range g.udp {
			if now.Unix()-f.seen.Load() > 120 {
				delete(g.udp, k)
				dead = append(dead, f)
			}
		}
		for a, t := range g.clients {
			if now.Sub(t) > 10*time.Minute {
				delete(g.clients, a)
			}
		}
		g.mu.Unlock()
		for _, f := range dead {
			f.up.Close()
		}
	}
}

// ---------- TCP ----------
func (g *gateway) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go g.tcpConn(c)
	}
}

func (g *gateway) tcpConn(c net.Conn) {
	defer c.Close()
	ra, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	ra = netip.AddrPortFrom(ra.Addr().Unmap(), ra.Port())
	g.mu.Lock()
	e := g.tcp[ra]
	g.mu.Unlock()
	if e == nil {
		return
	}
	dst := e.dst
	br := bufio.NewReaderSize(c, 16384)
	host := ""
	c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)) // протоколы, где первым говорит сервер
	if first, err := br.Peek(1); err == nil {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if first[0] == 0x16 {
			host = peekSNI(br)
		} else if first[0] >= 'A' && first[0] <= 'Z' {
			host = peekHTTPHost(br)
		}
	}
	c.SetReadDeadline(time.Time{})
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	up, err := g.tcpDial(host, dst)
	if err != nil {
		return
	}
	defer up.Close()
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		if _, err := up.Write(b); err != nil {
			return
		}
		br.Discard(n)
	}
	cc := &countConn{Conn: up, n: &g.nTCP}
	pipe(c, cc)
}

type countConn struct {
	net.Conn
	n *atomic.Int64
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.n.Add(int64(n))
	return n, err
}

func hostBypassed(host string, list []string) bool {
	host = strings.ToLower(host)
	for _, d := range list {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func (g *gateway) tcpDial(host string, dst netip.AddrPort) (net.Conn, error) {
	c := g.cfg.Load()
	target := dst.String()
	if host != "" && net.ParseIP(host) == nil {
		target = net.JoinHostPort(host, fmt.Sprint(dst.Port())) // по имени — без подменённых провайдером адресов
	}
	var ports []int
	switch {
	case host != "" && hostBypassed(host, c.Bypass):
	case host != "" && isGeoHost(host):
		ports = c.GeoHTTP
		if len(ports) == 0 && c.Mode == "vpn" {
			ports = c.HTTP
		}
	case c.Mode == "vpn":
		ports = c.HTTP
	}
	for _, p := range ports {
		if up, err := httpConnect(p, target); err == nil {
			return up, nil
		}
	}
	return net.DialTimeout("tcp", target, 10*time.Second)
}

func httpConnect(port int, target string) (net.Conn, error) {
	up, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return nil, err
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(up)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, " 200") {
		up.Close()
		return nil, errors.New("connect failed")
	}
	for { // остаток заголовков ответа
		l, err := br.ReadString('\n')
		if err != nil {
			up.Close()
			return nil, err
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	if br.Buffered() > 0 {
		up.Close()
		return nil, errors.New("unexpected data")
	}
	up.SetDeadline(time.Time{})
	return up, nil
}

// ---------- UDP ----------
type directUDP struct{ c *net.UDPConn }

func (d *directUDP) Send(b []byte) error { _, err := d.c.Write(b); return err }
func (d *directUDP) Recv(b []byte) (int, error) {
	d.c.SetReadDeadline(time.Now().Add(3 * time.Minute))
	return d.c.Read(b)
}
func (d *directUDP) Close() error { return d.c.Close() }

func (g *gateway) udpDial(c *gwConfig, dst netip.AddrPort) (udpUpstream, error) {
	if c.Mode == "vpn" {
		for _, p := range c.Socks {
			if s, err := socksUDPDial(p, dst); err == nil {
				return s, nil
			}
		}
	}
	u, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		return nil, err
	}
	return &directUDP{u}, nil
}

// SOCKS5 UDP ASSOCIATE к ядру Xray.
type socksUDP struct {
	ctl net.Conn
	u   *net.UDPConn
	hdr []byte
}

func socksUDPDial(port int, dst netip.AddrPort) (*socksUDP, error) {
	ctl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return nil, err
	}
	ctl.SetDeadline(time.Now().Add(5 * time.Second))
	fail := func(e error) (*socksUDP, error) { ctl.Close(); return nil, e }
	if _, err := ctl.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(ctl, r); err != nil || r[0] != 5 || r[1] != 0 {
		return fail(errors.New("socks auth"))
	}
	if _, err := ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(ctl, h); err != nil || h[1] != 0 {
		return fail(errors.New("socks udp associate"))
	}
	var bnd netip.AddrPort
	switch h[3] {
	case 1:
		a := make([]byte, 6)
		if _, err := io.ReadFull(ctl, a); err != nil {
			return fail(err)
		}
		bnd = netip.AddrPortFrom(netip.AddrFrom4([4]byte(a[:4])), binary.BigEndian.Uint16(a[4:]))
	case 4:
		a := make([]byte, 18)
		if _, err := io.ReadFull(ctl, a); err != nil {
			return fail(err)
		}
		bnd = netip.AddrPortFrom(netip.AddrFrom16([16]byte(a[:16])), binary.BigEndian.Uint16(a[16:]))
	default:
		return fail(errors.New("socks addr type"))
	}
	if !bnd.Addr().IsValid() || bnd.Addr().IsUnspecified() {
		bnd = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), bnd.Port())
	}
	ctl.SetDeadline(time.Time{})
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(bnd))
	if err != nil {
		return fail(err)
	}
	d4 := dst.Addr().As4()
	hdr := []byte{0, 0, 0, 1, d4[0], d4[1], d4[2], d4[3], byte(dst.Port() >> 8), byte(dst.Port())}
	s := &socksUDP{ctl: ctl, u: u, hdr: hdr}
	go func() { io.Copy(io.Discard, ctl); u.Close() }() // ядро закрыло связь — закрываем и поток
	return s, nil
}

func (s *socksUDP) Send(b []byte) error {
	_, err := s.u.Write(append(append([]byte(nil), s.hdr...), b...))
	return err
}

func (s *socksUDP) Recv(b []byte) (int, error) {
	buf := make([]byte, len(b)+300)
	for {
		s.u.SetReadDeadline(time.Now().Add(3 * time.Minute))
		n, err := s.u.Read(buf)
		if err != nil {
			return 0, err
		}
		if n < 10 || buf[2] != 0 {
			continue
		}
		off := 0
		switch buf[3] {
		case 1:
			off = 10
		case 4:
			off = 22
		case 3:
			off = 7 + int(buf[4])
		default:
			continue
		}
		if off > n {
			continue
		}
		return copy(b, buf[off:n]), nil
	}
}

func (s *socksUDP) Close() error { s.ctl.Close(); return s.u.Close() }

// ---------- конфигурация и состояние (файлы в папке данных) ----------
func readGWConfig() (*gwConfig, error) {
	b, err := os.ReadFile(gwConfigPath())
	if err != nil {
		return nil, err
	}
	var c gwConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (g *gateway) state(err string) gwState {
	g.mu.Lock()
	defer g.mu.Unlock()
	var cl []string
	for a := range g.clients {
		cl = append(cl, a.String())
	}
	return gwState{PID: os.Getpid(), TCP: g.nTCP.Load(), UDP: g.nUDP.Load(), Flows: len(g.udp) + len(g.tcp),
		Clients: strings.Join(cl, ", "), Err: err, TS: time.Now().Unix()}
}

func writeGWState(s gwState) {
	b, _ := json.Marshal(s)
	os.WriteFile(gwStatePath(), b, 0644)
}

func gwLog(format string, a ...any) { log.Printf("шлюз: "+format, a...) }

func readGWState() gwState {
	var s gwState
	if b, err := os.ReadFile(gwStatePath()); err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}
