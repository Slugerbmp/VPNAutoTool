package main

// Разбор ключа / подписки в список серверов (outbound'ы Xray).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	Name     string
	Outbound map[string]any
	Ping     int    // 0 — ещё не проверен, -1 — не отвечает, >0 — мс
	Err      string // причина, если не отвечает
	Kind     string // "" — для интернета; "special" — торренты и т.п. (только вручную); "info" — служебная строка подписки
}

var supported = map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "hysteria": true, "wireguard": true}

// parseInput принимает ссылку на подписку или сами ключи (vless://... по одному в строке).
// parseInput принимает ссылку на подписку или сами ключи (vless://... по одному в строке).
// Возвращает серверы и «сырое» тело подписки (для кэша).
func parseInput(key string, viaProxy string) ([]*Server, string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, "", errors.New("ключ пустой")
	}
	if strings.HasPrefix(key, "happ://") {
		return nil, "", errors.New("зашифрованные ключи happ:// не поддерживаются — нужна обычная ссылка на подписку (https://...) или ключ vless://...")
	}
	if strings.HasPrefix(key, "http://") || strings.HasPrefix(key, "https://") {
		var lastErr error
		type attempt struct {
			ua, proxy string
			system    bool
		}
		var tries []attempt
		for _, ua := range []string{"v2rayN/7.10.0", "Happ/2.0.0", "clash-verge/v2.2.0", "sing-box 1.11.0"} {
			tries = append(tries, attempt{ua, "", false}, attempt{ua, "", false}) // повтор при обрыве
			if viaProxy != "" {
				tries = append(tries, attempt{ua, viaProxy, false})
			}
			tries = append(tries, attempt{ua, "", true}) // системным механизмом (другой TLS, как у Happ)
		}
		for i, t := range tries {
			var body string
			var err error
			if t.system {
				body, err = fetchSystem(key, t.ua)
			} else {
				body, err = fetch(key, t.ua, t.proxy)
			}
			if err != nil {
				lastErr = err
				if i < len(tries)-1 {
					time.Sleep(700 * time.Millisecond)
				}
				continue
			}
			if servers := parseBody(body); len(servers) > 0 {
				return servers, body, nil
			}
			lastErr = errors.New("в подписке не найдено поддерживаемых серверов")
		}
		return nil, "", fmt.Errorf("не удалось загрузить подписку: %v", lastErr)
	}
	servers := parseBody(key)
	if len(servers) == 0 {
		return nil, "", errors.New("в ключе не найдено поддерживаемых серверов (vless, vmess, trojan, ss)")
	}
	return servers, key, nil
}

func fetch(u, ua, proxy string) (string, error) {
	tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, TLSHandshakeTimeout: 15 * time.Second}
	if proxy != "" {
		pu, _ := url.Parse(proxy)
		tr.Proxy = http.ProxyURL(pu)
	}
	cl := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", ua)
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("сервер подписки ответил %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	return string(b), err
}

func parseBody(text string) []*Server {
	t := strings.TrimSpace(strings.TrimPrefix(text, "\xef\xbb\xbf"))
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		return parseJSONSub(t)
	}
	if strings.HasPrefix(t, "<") {
		return nil
	}
	if strings.Contains(t, "\nproxies:") || strings.HasPrefix(t, "proxies:") {
		if s := parseClashYAML(t); len(s) > 0 {
			classifyServers(s)
			return s
		}
	}
	if !strings.Contains(t, "://") {
		if d, err := b64(t); err == nil {
			t = d
		}
	}
	var out []*Server
	defer func() { classifyServers(out) }()
	for _, line := range strings.Split(t, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "://") {
			continue
		}
		if s := parseLink(line); s != nil {
			out = append(out, s)
		}
	}
	return out
}

func b64(s string) (string, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", errors.New("не base64")
}

func unesc(s string) string {
	if r, err := url.PathUnescape(s); err == nil {
		return r
	}
	return s
}

// без превращения '+' в пробел (в отличие от url.ParseQuery)
func parseQuery(q string) map[string]string {
	m := map[string]string{}
	for _, p := range strings.Split(q, "&") {
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		v := ""
		if len(kv) == 2 {
			v = unesc(kv[1])
		}
		m[unesc(kv[0])] = v
	}
	return m
}

func get(q map[string]string, k, def string) string {
	if v, ok := q[k]; ok && v != "" {
		return v
	}
	return def
}

func stream(netw, sec string, q map[string]string, addr string) map[string]any {
	if netw == "" || netw == "raw" {
		netw = "tcp"
	}
	if netw == "splithttp" {
		netw = "xhttp"
	}
	s := map[string]any{"network": netw}
	switch netw {
	case "ws":
		s["wsSettings"] = map[string]any{"path": get(q, "path", "/"), "host": get(q, "host", "")}
	case "httpupgrade":
		s["httpupgradeSettings"] = map[string]any{"path": get(q, "path", "/"), "host": get(q, "host", "")}
	case "grpc":
		g := map[string]any{"serviceName": get(q, "serviceName", "")}
		if get(q, "mode", "") == "multi" {
			g["multiMode"] = true
		}
		if a := get(q, "authority", ""); a != "" {
			g["authority"] = a
		}
		s["grpcSettings"] = g
	case "xhttp":
		x := map[string]any{"path": get(q, "path", "/"), "host": get(q, "host", ""), "mode": get(q, "mode", "auto")}
		if e := get(q, "extra", ""); e != "" {
			var ex any
			if json.Unmarshal([]byte(e), &ex) == nil {
				x["extra"] = ex
			}
		}
		s["xhttpSettings"] = x
	}
	switch sec {
	case "tls":
		t := map[string]any{"serverName": get(q, "sni", get(q, "host", addr)), "fingerprint": get(q, "fp", "chrome")}
		if a := get(q, "alpn", ""); a != "" {
			t["alpn"] = strings.Split(a, ",")
		}
		s["security"] = "tls"
		s["tlsSettings"] = t
	case "reality":
		s["security"] = "reality"
		s["realitySettings"] = map[string]any{
			"serverName": get(q, "sni", ""), "fingerprint": get(q, "fp", "chrome"),
			"publicKey": get(q, "pbk", ""), "shortId": get(q, "sid", ""), "spiderX": get(q, "spx", ""),
		}
	}
	return s
}

func parseLink(line string) *Server {
	name := ""
	if i := strings.LastIndex(line, "#"); i >= 0 {
		name = strings.TrimSpace(unesc(line[i+1:]))
		line = line[:i]
	}
	scheme, rest, ok := strings.Cut(line, "://")
	if !ok {
		return nil
	}
	switch strings.ToLower(scheme) {
	case "vmess":
		return parseVmess(rest, name)
	case "vless", "trojan":
		return parseVlessTrojan(strings.ToLower(scheme), rest, name)
	case "ss":
		return parseSS(rest, name)
	case "hysteria2", "hy2":
		return parseHysteria2(rest, name)
	case "wireguard", "wg":
		return parseWireGuard(rest, name)
	}
	return nil
}

func parseVlessTrojan(proto, rest, name string) *Server {
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return nil
	}
	user := unesc(rest[:at])
	host, portS, err := net.SplitHostPort(rest[at+1:])
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portS)
	if err != nil {
		return nil
	}
	q := parseQuery(query)
	var settings map[string]any
	var sec string
	if proto == "vless" {
		settings = map[string]any{"vnext": []any{map[string]any{"address": host, "port": port,
			"users": []any{map[string]any{"id": user, "encryption": get(q, "encryption", "none"), "flow": get(q, "flow", "")}}}}}
		sec = get(q, "security", "none")
	} else {
		settings = map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "password": user}}}
		sec = get(q, "security", "tls")
	}
	if name == "" {
		name = host
	}
	return &Server{Name: name, Outbound: map[string]any{
		"protocol": proto, "settings": settings, "streamSettings": stream(get(q, "type", "tcp"), sec, q, host)}}
}

func parseVmess(rest, name string) *Server {
	d, err := b64(rest)
	if err != nil {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(d))
	dec.UseNumber()
	var j map[string]any
	if dec.Decode(&j) != nil {
		return nil
	}
	s := func(k string) string {
		if v, ok := j[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	port, _ := strconv.Atoi(s("port"))
	aid, _ := strconv.Atoi(s("aid"))
	q := map[string]string{}
	for _, k := range []string{"host", "path", "sni", "fp", "alpn"} {
		q[k] = s(k)
	}
	if s("net") == "grpc" {
		q["serviceName"] = s("path")
		q["mode"] = s("type")
	}
	scy := s("scy")
	if scy == "" {
		scy = "auto"
	}
	if n := s("ps"); n != "" {
		name = n
	}
	if name == "" {
		name = s("add")
	}
	return &Server{Name: name, Outbound: map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{"vnext": []any{map[string]any{"address": s("add"), "port": port,
			"users": []any{map[string]any{"id": s("id"), "alterId": aid, "security": scy}}}}},
		"streamSettings": stream(s("net"), s("tls"), q, s("add")),
	}}
}

func parseSS(rest, name string) *Server {
	if strings.Contains(rest, "plugin=") {
		return nil
	}
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	if !strings.Contains(rest, "@") {
		d, err := b64(rest)
		if err != nil {
			return nil
		}
		rest = d
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return nil
	}
	ui := unesc(rest[:at])
	if !strings.Contains(ui, ":") {
		d, err := b64(ui)
		if err != nil {
			return nil
		}
		ui = d
	}
	method, pass, _ := strings.Cut(ui, ":")
	host, portS, err := net.SplitHostPort(rest[at+1:])
	if err != nil {
		return nil
	}
	port, _ := strconv.Atoi(portS)
	if name == "" {
		name = host
	}
	return &Server{Name: name, Outbound: map[string]any{"protocol": "shadowsocks",
		"settings": map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "method": method, "password": pass}}}}}
}

// Подписка в виде полных JSON-конфигов Xray (так отдают некоторые панели).
func parseJSONSub(t string) (out []*Server) {
	defer func() { classifyServers(out) }()
	var data any
	if json.Unmarshal([]byte(t), &data) != nil {
		return nil
	}
	items, ok := data.([]any)
	if !ok {
		items = []any{data}
	}
	for _, it := range items {
		c, ok := it.(map[string]any)
		if !ok {
			continue
		}
		obs, _ := c["outbounds"].([]any)
		if len(obs) > 0 {
			if f, ok := obs[0].(map[string]any); ok {
				if _, isSB := f["type"]; isSB { // sing-box
					out = append(out, parseSingBox(obs)...)
					continue
				}
			}
		}
		if sv, ok := c["servers"].([]any); ok { // SIP008 (Shadowsocks)
			for _, x := range sv {
				if m, ok := x.(map[string]any); ok {
					p, _ := strconv.Atoi(str2(m["server_port"]))
					g := genericNode{Type: "ss", Name: str2(m["remarks"]), Server: str2(m["server"]), Port: p, Method: str2(m["method"]), Password: str2(m["password"])}
					if s := g.toServer(); s != nil {
						out = append(out, s)
					}
				}
			}
			continue
		}
		for _, o := range obs {
			ob, ok := o.(map[string]any)
			if !ok {
				continue
			}
			p, _ := ob["protocol"].(string)
			if !supported[p] {
				continue
			}
			delete(ob, "tag")
			if ss, ok := ob["streamSettings"].(map[string]any); ok {
				if so, ok := ss["sockopt"].(map[string]any); ok {
					delete(so, "dialerProxy")
				}
			}
			name, _ := c["remarks"].(string)
			if name == "" {
				name = fmt.Sprintf("Сервер %d", len(out)+1)
			}
			out = append(out, &Server{Name: name, Outbound: ob})
			break
		}
	}
	return out
}

// ---------- конфиг Xray ----------
// Каждый сервер получает свой локальный HTTP-вход 127.0.0.1:(basePort+i).
// Приложение само меряет пинг через каждый вход и направляет трафик в лучший.
func buildConfig(servers []*Server, directRu bool) []byte {
	var inbounds, outbounds, rules []any
	rules = append(rules, map[string]any{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"})
	if len(bypassList) > 0 {
		var ds []string
		for _, d := range bypassList {
			ds = append(ds, "domain:"+d)
		}
		rules = append(rules, map[string]any{"type": "field", "domain": ds, "outboundTag": "direct"})
	}
	if directRu {
		rules = append(rules,
			map[string]any{"type": "field", "domain": []string{"domain:ru", "domain:su", "domain:xn--p1ai"}, "outboundTag": "direct"},
			map[string]any{"type": "field", "ip": []string{"geoip:ru"}, "outboundTag": "direct"})
	}
	for i, s := range servers {
		in := fmt.Sprintf("in-%d", i)
		out := fmt.Sprintf("srv-%d", i)
		inbounds = append(inbounds, map[string]any{
			"tag": in, "listen": "127.0.0.1", "port": basePort + i, "protocol": "http",
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		})
		ob := map[string]any{"tag": out}
		for k, v := range s.Outbound {
			if k != "tag" {
				ob[k] = v
			}
		}
		outbounds = append(outbounds, ob)
		// SOCKS5 с UDP — для режима шлюза (голос Discord, игры)
		sk := fmt.Sprintf("sk-%d", i)
		inbounds = append(inbounds, map[string]any{
			"tag": sk, "listen": "127.0.0.1", "port": socksBase + i, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{in, sk}, "outboundTag": out})
	}
	outbounds = append(outbounds,
		map[string]any{"tag": "direct", "protocol": "freedom"},
		map[string]any{"tag": "block", "protocol": "blackhole"})
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(cfg)
	return buf.Bytes()
}

// ---------- назначение серверов по контексту ----------
var (
	reSpecial = regexp.MustCompile(`(?i)torrent|торрент|p2p|\bseed|качалк|download|скачиван`)
	reInfo    = regexp.MustCompile(`(?i)осталось|истека|истёк|expire|трафик|traffic|подписк|subscription|поддержк|support|тех\.?\s*поддерж|канал|сайт:|обнов|\bинфо\b|\binfo\b|баланс|продлить|оплат|telegram\.me|t\.me/|@[a-z0-9_]{4,}|\d{1,2}\.\d{1,2}\.\d{2,4}|дней|days left|\d+\s*(гб|gb|мб|mb)\b`)
)

func classifyServers(list []*Server) {
	for _, s := range list {
		addr := serverAddr(s.Outbound)
		port := 0
		if st, ok := s.Outbound["settings"].(map[string]any); ok {
			for _, k := range []string{"vnext", "servers"} {
				if arr, ok := st[k].([]any); ok && len(arr) > 0 {
					if m, ok := arr[0].(map[string]any); ok {
						switch p := m["port"].(type) {
						case int:
							port = p
						case float64:
							port = int(p)
						}
					}
				}
			}
		}
		switch {
		case addr == "" || addr == "0.0.0.0" || addr == "127.0.0.1" || addr == "localhost" || strings.HasPrefix(addr, "127.") || port <= 1:
			s.Kind = "info"
		case reInfo.MatchString(s.Name) && !reSpecial.MatchString(s.Name):
			s.Kind = "info"
		case reSpecial.MatchString(s.Name):
			s.Kind = "special"
		case isCIS(flagCountry(s.Name)):
			s.Kind = "cis" // сервер в СНГ: от блокировок не спасает — только вручную
		}
	}
}
