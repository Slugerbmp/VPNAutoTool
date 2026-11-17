//go:build windows

package main

// «Раздать точку доступа»: мобильный хот-спот Windows + прокси для подключившихся устройств.
// winws (запрет) не обрабатывает транзитный трафик раздачи, поэтому телефоны ходят через наш
// прокси: соединения тогда исходят от самого компьютера и проходят через VPN / запрет / WARP.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const hotspotSupported = true
const hotspotProxyPort = 10830

type hsState struct {
	State   string `json:"state"`
	Ssid    string `json:"ssid"`
	Pass    string `json:"pass"`
	Clients int    `json:"clients"`
	Error   string `json:"error"`
}

const hotspotScript = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
try {
  Add-Type -AssemblyName System.Runtime.WindowsRuntime
  $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation` + "`" + `1' })[0]
  function Await($t, $rt) { $a = $asTaskGeneric.MakeGenericMethod($rt); $n = $a.Invoke($null, @($t)); $n.Wait(-1) | Out-Null; $n.Result }
  $null = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
  $null = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
  $m = $null
  $profiles = @([Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()) + @([Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles())
  foreach ($p in $profiles) {
    if (-not $p) { continue }
    try { $m = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($p); if ($m) { break } } catch {}
  }
  if (-not $m) { throw 'Windows не может раздавать это подключение (нет подходящего Wi-Fi адаптера или подключения к интернету)' }
  $R = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]
  if ($env:VA_HS -eq 'start' -and $m.TetheringOperationalState -ne 'On') {
    $r = Await ($m.StartTetheringAsync()) $R
    if ([string]$r.Status -ne 'Success') { throw ('Windows не включил точку доступа: ' + $r.Status + ' ' + $r.AdditionalErrorMessage) }
  }
  if ($env:VA_HS -eq 'stop' -and $m.TetheringOperationalState -ne 'Off') { $null = Await ($m.StopTetheringAsync()) $R }
  $c = $m.GetCurrentAccessPointConfiguration()
  @{ state = [string]$m.TetheringOperationalState; ssid = $c.Ssid; pass = $c.Passphrase; clients = [int]$m.ClientCount } | ConvertTo-Json -Compress
} catch {
  @{ error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`

func hotspotPS(action string) (hsState, error) {
	cmd := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePSScript(hotspotScript))
	cmd.Env = append(os.Environ(), "VA_HS="+action)
	out, err := cmd.Output()
	var s hsState
	txt := strings.TrimSpace(decodeOEM(out))
	if i := strings.LastIndex(txt, "{"); i >= 0 {
		txt = txt[i:]
	}
	if json.Unmarshal([]byte(txt), &s) != nil {
		if err == nil {
			err = errors.New("не удалось получить состояние точки доступа")
		}
		return s, err
	}
	if s.Error != "" {
		return s, errors.New(s.Error)
	}
	return s, nil
}

func encodePSScript(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[2*i], b[2*i+1] = byte(v), byte(v>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// ---------- прокси для устройств в раздаче ----------
var (
	hsMu       sync.Mutex
	hsListener net.Listener
	hsIP       string
)

func hotspotIP() string {
	ifs, _ := net.Interfaces()
	for _, in := range ifs {
		addrs, _ := in.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil && ip4[0] == 192 && ip4[1] == 168 && ip4[2] == 137 {
					return ip4.String()
				}
			}
		}
	}
	return ""
}

// Адрес компьютера в домашней/рабочей сети (проводной или Wi-Fi), без виртуальных адаптеров.
func lanIP() string {
	ifs, _ := net.Interfaces()
	skip := []string{"warp", "cloudflare", "wintun", "tun", "tap", "vethernet", "virtualbox", "vmware", "hyper-v", "loopback", "bluetooth", "zerotier", "radmin", "hamachi"}
	best := ""
	for _, in := range ifs {
		if in.Flags&net.FlagUp == 0 || in.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(in.Name)
		bad := false
		for _, s := range skip {
			if strings.Contains(name, s) {
				bad = true
			}
		}
		if bad {
			continue
		}
		addrs, _ := in.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP.To4()
			if ip == nil || (ip[0] == 192 && ip[1] == 168 && ip[2] == 137) || (ip[0] == 172 && ip[1] == 16 && ip[2] == 0) {
				continue
			}
			private := ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168)
			if private {
				if strings.Contains(name, "ethernet") || strings.Contains(name, "подключение по локальной") {
					return ip.String() // проводное — в приоритете
				}
				if best == "" {
					best = ip.String()
				}
			}
		}
	}
	return best
}

// lan=false — адрес Wi-Fi точки доступа Windows; lan=true — адрес в локальной сети.
func hotspotProxyStart(lan bool) error {
	hsMu.Lock()
	defer hsMu.Unlock()
	if hsListener != nil {
		return nil
	}
	var ip string
	for i := 0; i < 20 && ip == ""; i++ {
		if lan {
			ip = lanIP()
		} else {
			ip = hotspotIP()
		}
		if ip == "" {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if ip == "" {
		if lan {
			return errors.New("не найден адрес компьютера в локальной сети — проверьте подключение кабеля или Wi-Fi")
		}
		return errors.New("точка доступа включилась, но её адрес не найден")
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, hotspotProxyPort))
	if err != nil {
		return fmt.Errorf("не удалось открыть порт для раздачи: %v", err)
	}
	hsListener, hsIP = ln, ip
	// Telegram на телефоне не пользуется системным прокси — для него отдельный вход:
	// пересылка к TG WS Proxy этого компьютера (MTProto-прокси с секретом)
	if tl, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, hotspotTGPort)); err == nil {
		hsTGListener = tl
		go func() {
			for {
				c, err := tl.Accept()
				if err != nil {
					return
				}
				go serveTGRelay(c)
			}
		}()
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go app.serveHotspotConn(c)
		}
	}()
	return nil
}

func hotspotProxyStop() {
	hsMu.Lock()
	defer hsMu.Unlock()
	if hsListener != nil {
		hsListener.Close()
		hsListener, hsIP = nil, ""
	}
	if hsTGListener != nil {
		hsTGListener.Close()
		hsTGListener = nil
	}
}

const hotspotTGPort = 10831

var hsTGListener net.Listener

func serveTGRelay(c net.Conn) {
	defer c.Close()
	_, port, secret := tgwsConf()
	if secret == "" || !tgwsRunning() {
		return
	}
	up, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	pipe(c, up)
}

// tgShareLinks — ссылки для Telegram на телефоне: через TG WS Proxy (если запущен) и SOCKS5.
func tgShareLinks() (mtproto, socks string) {
	hsMu.Lock()
	ip, tgOK := hsIP, hsTGListener != nil
	hsMu.Unlock()
	if ip == "" {
		return "", ""
	}
	socks = fmt.Sprintf("tg://socks?server=%s&port=%d", ip, hotspotProxyPort)
	if _, _, secret := tgwsConf(); tgOK && secret != "" && tgwsRunning() {
		mtproto = fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", ip, hotspotTGPort, secret)
	}
	return
}

func hotspotProxyAddr() string {
	hsMu.Lock()
	defer hsMu.Unlock()
	if hsListener == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", hsIP, hotspotProxyPort)
}

// VPN включён — отдаём соединение в выбранный сервер Xray; иначе — свой прокси «напрямую»
// (через запрет и WARP, раз соединение исходит от компьютера).
func (a *App) serveHotspotConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	head, err := br.Peek(5)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	if string(head) == "GET /" { // запрос файла автонастройки proxy.pac
		servePAC(c, br)
		return
	}
	a.mu.Lock()
	vpn, idx := a.on, a.cur
	a.mu.Unlock()
	port := basePort + idx
	if head[0] == 0x05 { // SOCKS5 — так подключается Telegram (ссылка tg://socks)
		if !(vpn && idx >= 0 && coreRunning()) {
			socksDirect(c, br)
			return
		}
		port = socksBase + idx // SOCKS5-вход ядра выбранного сервера
	}
	if vpn && idx >= 0 && coreRunning() {
		up, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
		if err != nil {
			return
		}
		defer up.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(up, br); done <- struct{}{} }()
		go func() { io.Copy(c, up); done <- struct{}{} }()
		<-done
		return
	}
	directProxy(c, br)
}

func servePAC(c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	addr := hotspotProxyAddr()
	var sb strings.Builder
	sb.WriteString("function FindProxyForURL(url, host) {\n")
	sb.WriteString("  if (isPlainHostName(host) || shExpMatch(host, \"*.local\") || isInNet(dnsResolve(host), \"10.0.0.0\", \"255.0.0.0\") ||\n")
	sb.WriteString("      isInNet(dnsResolve(host), \"172.16.0.0\", \"255.240.0.0\") || isInNet(dnsResolve(host), \"192.168.0.0\", \"255.255.0.0\")) return \"DIRECT\";\n")
	for _, d := range bypassList {
		sb.WriteString(fmt.Sprintf("  if (dnsDomainIs(host, %q) || host == %q) return \"DIRECT\";\n", "."+d, d))
	}
	sb.WriteString(fmt.Sprintf("  return \"PROXY %s; DIRECT\";\n}\n", addr))
	body := sb.String()
	status := "200 OK"
	if !strings.HasSuffix(req.URL.Path, ".pac") {
		status, body = "404 Not Found", "not found"
	}
	fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, len(body), body)
}

var directTransport = &http.Transport{Proxy: nil, MaxIdleConns: 50, IdleConnTimeout: 60 * time.Second}

func directProxy(c net.Conn, br *bufio.Reader) {
	for {
		c.SetReadDeadline(time.Now().Add(2 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		c.SetReadDeadline(time.Time{})
		if req.Method == http.MethodConnect {
			up, err := net.DialTimeout("tcp", req.Host, 15*time.Second)
			if err != nil {
				c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
				return
			}
			defer up.Close()
			c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			if n := br.Buffered(); n > 0 {
				b, _ := br.Peek(n)
				up.Write(b)
				br.Discard(n)
			}
			pipe(c, up)
			return
		}
		if req.URL.Host == "" {
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		req.RequestURI = ""
		for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive"} {
			req.Header.Del(h)
		}
		resp, err := directTransport.RoundTrip(req)
		if err != nil {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		err = resp.Write(c)
		resp.Body.Close()
		if err != nil || req.Close || resp.Close {
			return
		}
	}
}

// socksDirect — простой SOCKS5 (без пароля, только CONNECT): соединение исходит от компьютера,
// значит на него действуют запрет и WARP.
func socksDirect(c net.Conn, br *bufio.Reader) {
	c.SetDeadline(time.Now().Add(20 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 5 {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 { // только CONNECT
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1])))
	up, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	c.SetDeadline(time.Time{})
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		up.Write(b)
		br.Discard(n)
	}
	pipe(c, up)
}
