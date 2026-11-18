package main

// Режим для приставок (Xbox, PlayStation, Smart TV): у них нет настроек прокси,
// поэтому компьютер становится их DNS-сервером. Для заблокированных сайтов
// (YouTube, Discord, Instagram, … и всё из списков запрета) DNS отвечает адресом
// компьютера, а он принимает соединения на 443/80, по SNI/Host узнаёт сайт и
// ведёт трафик через VPN (если включён) или напрямую — то есть через запрет/WARP.
// Остальные запросы (игры, PSN, Xbox Live) уходят в обычный DNS — как без нас.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var cons = struct {
	sync.Mutex
	on      bool
	ip      string
	udp     *net.UDPConn
	lns     []net.Listener
	domains map[string]bool
	err     string
	queries int // сколько DNS-запросов пришло (для подсказки «приставка не обращается»)
}{}

var consoleExtra = []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtubei.googleapis.com",
	"youtube-nocookie.com", "yt.be", "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.app",
	"twitch.tv", "ttvnw.net", "jtvnw.net", "x.com", "twitter.com", "twimg.com"}

// голос и игровые сервера ходят по UDP — их не трогаем
var consoleNever = []string{"discord.media", "playstation.net", "playstation.com", "sonyentertainmentnetwork.com", "scea.com",
	"xboxlive.com", "xbox.com", "xboxservices.com", "xboxab.com", "gamepass.com", "xbox.net", "microsoft.com", "live.com",
	"live.net", "microsoftonline.com", "msauth.net", "msftauth.net", "msidentity.com", "gfx.ms", "msftconnecttest.com",
	"msftncsi.com", "windowsupdate.com", "windows.com", "windows.net", "azureedge.net", "azurefd.net", "trafficmanager.net",
	"cloudapp.net", "footprintdns.com", "s-microsoft.com", "akamai.net", "akamaized.net", "akamaiedge.net", "akamaihd.net",
	"edgekey.net", "edgesuite.net", "nintendo.net", "nintendo.com", "steamcontent.com", "steamserver.net", "epicgames.com", "ea.com"}

func consoleDomains() map[string]bool {
	m := map[string]bool{}
	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !strings.HasPrefix(d, "#") && strings.Contains(d, ".") {
			m[strings.Trim(d, ".")] = true
		}
	}
	for _, d := range vpnautoDomains {
		add(d)
	}
	for _, d := range consoleExtra {
		add(d)
	}
	for _, d := range zapretExtra {
		add(d)
	}
	// только пользовательский список запрета: общий список слишком широк (там есть CDN,
	// через которые ходят службы Xbox/PSN — их подмена ломает вход, ошибка 0x80a40401)
	for _, f := range []string{"list-general-user.txt"} {
		if b, err := os.ReadFile(filepath.Join(zapretDir(), "lists", f)); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				add(l)
			}
		}
	}
	for _, d := range append(append([]string{}, consoleNever...), bypassList...) {
		delete(m, d)
	}
	return m
}

// Вход в Xbox: Microsoft не пускает российские адреса («Вы находитесь в регионе, где эта
// служба недоступна», 0x80a40401). Эти адреса всегда ведём через ПК — то есть через VPN
// (или WARP), чтобы вход шёл с зарубежного адреса. Остальное Xbox Live — напрямую.
// Проверку региона Microsoft делает не только на серверах входа, поэтому через зарубежный
// выход ведём все службы аккаунта Xbox (кроме скачивания игр — они тяжёлые и региона не проверяют).
var consoleGeo = []string{
	// TikTok не показывает ленту российским адресам — тоже только через зарубежный выход
	"tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokv.eu", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com",
	"tiktokw.us", "tiktokw.eu", "tiktokd.org", "tiktokd.net", "tik-tokapi.com", "ttwstatic.com", "musical.ly", "muscdn.com",
	"byteoversea.com", "byteoversea.net", "ibytedtos.com", "ibyteimg.com", "ipstatp.com", "bytefcdn-oversea.com",
	"byteintlapi.com", "bytegecko-i18n.com", "isnssdk.com", "sgsnssdk.com", "tiktokrow-cdn.com", "tiktokeu-cdn.com", "ttlivecdn.com",
	"xboxlive.com", "xbox.com", "xboxservices.com", "xboxab.com", "gamepass.com", "xbox.net",
	"live.com", "live.net", "microsoftonline.com", "msauth.net", "msftauth.net", "msidentity.com", "gfx.ms",
	"mp.microsoft.com", "xboxlive.cn", "account.microsoft.com", "login.microsoft.com", "storeedgefd.dsx.mp.microsoft.com"}

// скачивание игр и обновлений — напрямую (не тратим VPN и не тормозим загрузку)
var consoleGeoExcept = []string{"assets1.xboxlive.com", "assets2.xboxlive.com", "dlassets.xboxlive.com", "dlassets2.xboxlive.com",
	"d1.xboxlive.com", "d2.xboxlive.com", "xvcf1.xboxlive.com", "xvcf2.xboxlive.com", "xbox-mbr.xboxlive.com",
	"assets.xbox.com", "download.xbox.com", "delivery.mp.microsoft.com", "do.dsp.mp.microsoft.com", "dl.delivery.mp.microsoft.com",
	"tlu.dl.delivery.mp.microsoft.com", "emdl.ws.microsoft.com", "windowsupdate.com", "update.microsoft.com"}

func hostIn(host string, list []string) bool {
	for _, d := range list {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func matchDomain(m map[string]bool, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if isGeoHost(host) {
		return true
	}
	for _, d := range append(append([]string{}, consoleNever...), bypassList...) {
		if host == d || strings.HasSuffix(host, "."+d) {
			return false
		}
	}
	for h := host; h != ""; {
		if m[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return false
}

// Запустить на адресе раздачи; при занятом 53-м порту (служба общего доступа Windows)
// пробуем адрес компьютера в локальной сети.
func consoleStart(ips ...string) error {
	cons.Lock()
	defer cons.Unlock()
	if cons.on {
		return nil
	}
	cons.domains = consoleDomains()
	var lastErr error
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: 53})
		if err != nil {
			lastErr = fmt.Errorf("порт DNS 53 на %s занят", ip)
			continue
		}
		var lns []net.Listener
		ok := true
		for _, p := range []int{443, 80, 53} {
			ln, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", ip, p))
			if err != nil {
				lastErr = fmt.Errorf("порт %d на %s занят другой программой", p, ip)
				ok = false
				break
			}
			lns = append(lns, ln)
		}
		if !ok {
			u.Close()
			for _, l := range lns {
				l.Close()
			}
			continue
		}
		cons.on, cons.ip, cons.udp, cons.lns, cons.err, cons.queries = true, ip, u, lns, "", 0
		go dnsServe(u)
		go acceptLoop(lns[0], 443)
		go acceptLoop(lns[1], 80)
		go dnsServeTCP(lns[2])
		log.Printf("режим приставок: DNS %s (%d доменов)", ip, len(cons.domains))
		go app.geoLoop()
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("нет адреса для раздачи")
	}
	cons.err = lastErr.Error()
	return lastErr
}

func consoleStop() {
	cons.Lock()
	defer cons.Unlock()
	if !cons.on {
		return
	}
	cons.udp.Close()
	for _, l := range cons.lns {
		l.Close()
	}
	cons.on, cons.ip, cons.udp, cons.lns = false, "", nil, nil
}

func consoleAddr() (string, string, int) {
	cons.Lock()
	defer cons.Unlock()
	return cons.ip, cons.err, cons.queries
}

// DNS по TCP (длинные ответы, у Xbox бывают) — длина 2 байта + сообщение.
func dnsServeTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				cons.Lock()
				cons.queries++
				cons.Unlock()
				r := dnsAnswerTCP(q)
				if r == nil {
					return
				}
				binary.BigEndian.PutUint16(l[:], uint16(len(r)))
				if _, err := c.Write(append(l[:], r...)); err != nil {
					return
				}
			}
		}()
	}
}

// Ответ для TCP: свои ответы — как в UDP, остальное — к внешнему DNS по TCP (без обрезки).
func dnsAnswerTCP(q []byte) []byte {
	name, _, _, ok := dnsQuestion(q)
	cons.Lock()
	ip, dom := cons.ip, cons.domains
	cons.Unlock()
	if ok && ip != "" && matchDomain(dom, name) {
		return dnsAnswer(q)
	}
	if ok {
		dnsLogName(name, false)
	}
	for _, up := range localUpstreams() {
		c, err := net.DialTimeout("tcp", up, 3*time.Second)
		if err != nil {
			continue
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(q)))
		c.Write(append(l[:], q...))
		if _, err := io.ReadFull(c, l[:]); err == nil {
			r := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(c, r); err == nil {
				c.Close()
				return r
			}
		}
		c.Close()
	}
	return nil
}

// ---------- DNS ----------
var dnsUpstreams = []string{"1.1.1.1:53", "8.8.8.8:53", "77.88.8.8:53"}

func dnsServe(u *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := u.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		cons.Lock()
		cons.queries++
		cons.Unlock()
		devSeen(from.IP.String(), "DNS", false)
		go func() {
			if r := dnsAnswer(q); r != nil {
				u.WriteToUDP(r, from)
			}
		}()
	}
}

// Разбор вопроса: имя, тип, конец вопроса.
func dnsQuestion(q []byte) (name string, qtype uint16, end int, ok bool) {
	if len(q) < 17 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return
	}
	i := 12
	var labels []string
	for i < len(q) {
		l := int(q[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 || i+1+l > len(q) {
			return
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(q) {
		return
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(q[i : i+2]), i + 4, true
}

// Журнал имён, которые спрашивает приставка (каждое один раз) — для диагностики.
var dnsSeen = struct {
	sync.Mutex
	m map[string]bool
}{m: map[string]bool{}}

func dnsLogName(name string, redirected bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return
	}
	dnsSeen.Lock()
	defer dnsSeen.Unlock()
	if dnsSeen.m[name] || len(dnsSeen.m) > 3000 {
		return
	}
	dnsSeen.m[name] = true
	how := "напрямую"
	if isGeoHost(name) {
		how = "через ПК → за границу (вход Xbox)"
	} else if redirected {
		how = "через ПК"
	}
	if dataDir == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(dataDir, "console-dns.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		fmt.Fprintf(f, "%s  %s  %s\n", time.Now().Format("15:04:05"), name, how)
		f.Close()
	}
}

func dnsAnswer(q []byte) []byte {
	name, qtype, end, ok := dnsQuestion(q)
	cons.Lock()
	ip, dom := cons.ip, cons.domains
	cons.Unlock()
	if ok {
		dnsLogName(name, ip != "" && matchDomain(dom, name))
	}
	if ok && ip != "" && matchDomain(dom, name) {
		r := make([]byte, end, end+16)
		copy(r, q[:end])
		r[2] = 0x80 | (q[2] & 0x01) // QR=1, RD как в запросе
		r[3] = 0x80                 // RA=1, RCODE=0
		binary.BigEndian.PutUint16(r[6:8], 0)
		binary.BigEndian.PutUint16(r[8:10], 0)
		binary.BigEndian.PutUint16(r[10:12], 0)
		if qtype == 1 { // A → адрес компьютера; AAAA/HTTPS → пусто, чтобы шли по IPv4 к нам
			binary.BigEndian.PutUint16(r[6:8], 1)
			r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			r = append(r, net.ParseIP(ip).To4()...)
		}
		return r
	}
	// спрашиваем сразу роутер (как приставка спросила бы сама) и публичные DNS — берём первый ответ
	ups := localUpstreams()
	res := make(chan []byte, len(ups))
	for _, up := range ups {
		go func(up string) {
			c, err := net.DialTimeout("udp", up, 2*time.Second)
			if err != nil {
				res <- nil
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			c.Write(q)
			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			if err != nil || n < 12 || buf[0] != q[0] || buf[1] != q[1] {
				res <- nil
				return
			}
			res <- buf[:n]
		}(up)
	}
	var fallback []byte
	for range ups {
		r := <-res
		if r == nil {
			continue
		}
		if r[3]&0x0f == 0 || r[3]&0x0f == 3 { // NOERROR / NXDOMAIN — нормальный ответ
			return r
		}
		fallback = r // SERVFAIL/REFUSED — подождём остальных
	}
	return fallback
}

// Предполагаемый адрес роутера (x.x.x.1), если это не мы сами (у точки доступа Windows мы и есть .1).
func routerGuess(ip string) string {
	p := net.ParseIP(ip).To4()
	if p == nil || p[3] == 1 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.1", p[0], p[1], p[2])
}

// Роутер локальной сети и публичные DNS.
func localUpstreams() []string {
	cons.Lock()
	ip := cons.ip
	cons.Unlock()
	var ups []string
	if r := routerGuess(ip); r != "" {
		ups = append(ups, r+":53")
	}
	return append(ups, dnsUpstreams...)
}

// ---------- 443 (SNI) и 80 (Host) ----------
func acceptLoop(ln net.Listener, port int) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go consoleConn(trackConn(c, "DNS"), port)
	}
}

func consoleConn(c net.Conn, port int) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 16384)
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	var host string
	if port == 443 {
		host = peekSNI(br)
	} else {
		host = peekHTTPHost(br)
	}
	c.SetReadDeadline(time.Time{})
	if host == "" {
		return
	}
	// не допускаем петлю на самих себя
	if ip := net.ParseIP(host); ip != nil {
		return
	}
	var up net.Conn
	var err error
	if isGeoHost(host) {
		up, err = app.dialGeo(net.JoinHostPort(host, fmt.Sprint(port)))
	} else {
		up, err = app.dialOut(host, port)
	}
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
	pipe(c, up)
}

// Соединение наружу: через выбранный сервер VPN или напрямую (запрет/WARP действуют на трафик компьютера).
func (a *App) dialOut(host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, fmt.Sprint(port))
	a.mu.Lock()
	vpn, idx := a.on, a.cur
	var alive []int // запасные: остальные отвечающие серверы (кроме торрентных/служебных)
	for i, s := range a.servers {
		if i != idx && s.Ping > 0 && s.Kind == "" && len(alive) < 4 {
			alive = append(alive, i)
		}
	}
	a.mu.Unlock()
	bypass := false
	for _, d := range bypassList {
		if host == d || strings.HasSuffix(host, "."+d) {
			bypass = true
		}
	}
	if vpn && idx >= 0 && coreRunning() && !bypass {
		for _, i := range append([]int{idx}, alive...) {
			if up, err := dialViaCore(i, target); err == nil {
				return up, nil
			}
		}
		// выбранный сервер не отвечает — пробуем напрямую (через запрет/WARP), лучше чем ничего
	}
	return net.DialTimeout("tcp", target, 15*time.Second)
}

func dialViaCore(idx int, target string) (net.Conn, error) {
	{
		up, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+idx), 2*time.Second)
		if err != nil {
			return nil, err
		}
		up.SetDeadline(time.Now().Add(15 * time.Second))
		fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		r := bufio.NewReader(up)
		resp, err := http.ReadResponse(r, nil)
		if err != nil || resp.StatusCode != 200 || r.Buffered() > 0 {
			up.Close()
			return nil, errors.New("vpn connect failed")
		}
		up.SetDeadline(time.Time{})
		return up, nil
	}
}

func peekHTTPHost(br *bufio.Reader) string {
	n := 1
	for n <= 8192 {
		b, err := br.Peek(n) // ждём хотя бы ещё один байт
		if err != nil {
			return ""
		}
		b, _ = br.Peek(br.Buffered())
		s := string(b)
		if i := strings.Index(strings.ToLower(s), "\r\nhost:"); i >= 0 {
			rest := s[i+7:]
			if j := strings.Index(rest, "\r\n"); j >= 0 {
				h := strings.TrimSpace(rest[:j])
				if hh, _, e := net.SplitHostPort(h); e == nil {
					h = hh
				}
				return h
			}
		}
		if strings.Contains(s, "\r\n\r\n") {
			return ""
		}
		n = len(b) + 1
	}
	return ""
}

// Имя сайта из TLS ClientHello (без расшифровки).
func peekSNI(br *bufio.Reader) string {
	hdr, err := br.Peek(5)
	if err != nil || hdr[0] != 0x16 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen > 16384 {
		recLen = 16384
	}
	b, err := br.Peek(5 + recLen)
	if err != nil {
		return ""
	}
	return parseSNI(b[5:])
}

func parseSNI(h []byte) string {
	// Handshake: type(1)=1 len(3) ver(2) random(32) sid(1+n) ciphers(2+n) comp(1+n) ext(2+n)
	if len(h) < 42 || h[0] != 1 {
		return ""
	}
	p := 38
	skip := func(lenBytes int) bool {
		if p+lenBytes > len(h) {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(h[p+i])
		}
		p += lenBytes + n
		return p <= len(h)
	}
	if !skip(1) || !skip(2) || !skip(1) || p+2 > len(h) {
		return ""
	}
	end := p + 2 + int(binary.BigEndian.Uint16(h[p:p+2]))
	p += 2
	if end > len(h) {
		end = len(h)
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(h[p : p+2])
		l := int(binary.BigEndian.Uint16(h[p+2 : p+4]))
		p += 4
		if p+l > end {
			return ""
		}
		if typ == 0 && l >= 5 { // server_name
			e := h[p : p+l]
			if e[2] == 0 {
				nl := int(binary.BigEndian.Uint16(e[3:5]))
				if 5+nl <= len(e) {
					return string(e[5 : 5+nl])
				}
			}
			return ""
		}
		p += l
	}
	return ""
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// consoleRefreshDomains — после изменения списков сайтов приставки сразу получают новый список.
func consoleRefreshDomains() {
	cons.Lock()
	if cons.on {
		cons.domains = consoleDomains()
	}
	cons.Unlock()
}
