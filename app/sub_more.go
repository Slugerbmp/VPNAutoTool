package main

// Дополнительные форматы подписок: hysteria2://, wireguard://, sing-box JSON, Clash YAML.

import (
	"strconv"
	"strings"
)

// hysteria2://auth@host:port?sni=..&obfs=salamander&obfs-password=..&insecure=1#name (также hy2://)
func parseHysteria2(rest, name string) *Server {
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	auth := ""
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		auth, rest = unesc(rest[:at]), rest[at+1:]
	}
	host, portS := splitHostPortLoose(rest)
	if host == "" {
		return nil
	}
	port := firstPort(portS, 443)
	q := parseQuery(query)
	if auth == "" {
		auth = get(q, "auth", get(q, "password", ""))
	}
	if name == "" {
		name = host
	}
	return &Server{Name: name, Outbound: hy2Outbound(host, port, auth, get(q, "sni", get(q, "peer", "")), get(q, "obfs", ""), get(q, "obfs-password", ""), get(q, "alpn", ""))}
}

func hy2Outbound(host string, port int, auth, sni, obfs, obfsPass, alpn string) map[string]any {
	if sni == "" {
		sni = host
	}
	tls := map[string]any{"serverName": sni, "alpn": []string{"h3"}}
	if alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	ss := map[string]any{
		"network":          "hysteria",
		"hysteriaSettings": map[string]any{"version": 2, "auth": auth},
		"security":         "tls",
		"tlsSettings":      tls,
	}
	if strings.EqualFold(obfs, "salamander") && obfsPass != "" {
		ss["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": obfsPass}}}}
	}
	return map[string]any{
		"protocol":       "hysteria",
		"settings":       map[string]any{"version": 2, "address": host, "port": port},
		"streamSettings": ss,
	}
}

// wireguard://privateKey@host:port?publickey=..&address=10.0.0.2/32,fd00::2/128&mtu=1280&reserved=1,2,3&presharedkey=..#name
func parseWireGuard(rest, name string) *Server {
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return nil
	}
	priv := unesc(rest[:at])
	host, portS := splitHostPortLoose(rest[at+1:])
	q := parseQuery(query)
	if name == "" {
		name = host
	}
	return &Server{Name: name, Outbound: wgOutbound(host, firstPort(portS, 51820), priv,
		get(q, "publickey", get(q, "public_key", get(q, "peer_public_key", ""))),
		get(q, "presharedkey", get(q, "pre_shared_key", "")),
		get(q, "address", get(q, "ip", "10.0.0.2/32")), get(q, "reserved", ""), get(q, "mtu", ""))}
}

func wgOutbound(host string, port int, priv, pub, psk, addrs, reserved, mtu string) map[string]any {
	var address []string
	for _, a := range strings.Split(addrs, ",") {
		if a = strings.TrimSpace(a); a != "" {
			if !strings.Contains(a, "/") {
				if strings.Contains(a, ":") {
					a += "/128"
				} else {
					a += "/32"
				}
			}
			address = append(address, a)
		}
	}
	peer := map[string]any{"publicKey": pub, "endpoint": joinHostPort(host, port)}
	if psk != "" {
		peer["preSharedKey"] = psk
	}
	st := map[string]any{"secretKey": priv, "address": address, "peers": []any{peer}}
	if m, err := strconv.Atoi(mtu); err == nil && m > 0 {
		st["mtu"] = m
	} else {
		st["mtu"] = 1280
	}
	if reserved != "" {
		var r []int
		for _, x := range strings.Split(reserved, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
				r = append(r, n)
			}
		}
		if len(r) == 3 {
			st["reserved"] = r
		}
	}
	return map[string]any{"protocol": "wireguard", "settings": st}
}

func splitHostPortLoose(s string) (string, string) {
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			return s[1:i], strings.TrimPrefix(s[i+1:], ":")
		}
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && strings.Count(s, ":") == 1 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// порт может быть списком/диапазоном («443,5000-6000») — берём первый
func firstPort(s string, def int) int {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, ",-"); i >= 0 {
		s = s[:i]
	}
	if p, err := strconv.Atoi(s); err == nil && p > 0 {
		return p
	}
	return def
}

func joinHostPort(h string, p int) string {
	if strings.Contains(h, ":") {
		return "[" + h + "]:" + strconv.Itoa(p)
	}
	return h + ":" + strconv.Itoa(p)
}

// ---------- общий конвертер «поля → outbound Xray» (для sing-box и Clash) ----------
type genericNode struct {
	Type, Name, Server   string
	Port                 int
	UUID, Password       string
	Method, Flow         string
	AlterID              int
	TLS, Reality         bool
	SNI, FP, ALPN        string
	PBK, SID             string
	Net, Path, Host      string
	Service              string
	ObfsType, ObfsPass   string
	WGPriv, WGPub, WGPSK string
	WGAddr, WGReserved   string
	WGMTU                int
}

func (g genericNode) toServer() *Server {
	if g.Server == "" || g.Port == 0 {
		return nil
	}
	name := g.Name
	if name == "" {
		name = g.Server
	}
	q := map[string]string{"sni": g.SNI, "fp": g.FP, "alpn": g.ALPN, "pbk": g.PBK, "sid": g.SID,
		"path": g.Path, "host": g.Host, "serviceName": g.Service, "flow": g.Flow}
	sec := "none"
	if g.Reality {
		sec = "reality"
	} else if g.TLS {
		sec = "tls"
	}
	netw := g.Net
	switch netw {
	case "", "tcp":
		netw = "tcp"
	case "http", "h2":
		netw = "xhttp"
	}
	var ob map[string]any
	switch strings.ToLower(g.Type) {
	case "vless":
		ob = map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": g.Server, "port": g.Port,
			"users": []any{map[string]any{"id": g.UUID, "encryption": "none", "flow": g.Flow}}}}},
			"streamSettings": stream(netw, sec, q, g.Server)}
	case "vmess":
		ob = map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{"address": g.Server, "port": g.Port,
			"users": []any{map[string]any{"id": g.UUID, "alterId": g.AlterID, "security": "auto"}}}}},
			"streamSettings": stream(netw, sec, q, g.Server)}
	case "trojan":
		if sec == "none" {
			sec = "tls"
		}
		ob = map[string]any{"protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{"address": g.Server, "port": g.Port, "password": g.Password}}},
			"streamSettings": stream(netw, sec, q, g.Server)}
	case "ss", "shadowsocks":
		ob = map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": g.Server, "port": g.Port, "method": g.Method, "password": g.Password}}}}
	case "hysteria2", "hy2":
		ob = hy2Outbound(g.Server, g.Port, g.Password, g.SNI, g.ObfsType, g.ObfsPass, g.ALPN)
	case "wireguard", "wg":
		ob = wgOutbound(g.Server, g.Port, g.WGPriv, g.WGPub, g.WGPSK, g.WGAddr, g.WGReserved, strconv.Itoa(g.WGMTU))
	default:
		return nil
	}
	return &Server{Name: name, Outbound: ob}
}

// ---------- sing-box JSON ----------
func parseSingBox(outbounds []any) []*Server {
	var out []*Server
	for _, o := range outbounds {
		m, ok := o.(map[string]any)
		if !ok {
			continue
		}
		str := func(mm map[string]any, k string) string {
			if v, ok := mm[k]; ok && v != nil {
				switch x := v.(type) {
				case string:
					return x
				case float64:
					return strconv.Itoa(int(x))
				case []any:
					var p []string
					for _, e := range x {
						p = append(p, str2(e))
					}
					return strings.Join(p, ",")
				}
			}
			return ""
		}
		sub := func(mm map[string]any, k string) map[string]any {
			if v, ok := mm[k].(map[string]any); ok {
				return v
			}
			return map[string]any{}
		}
		g := genericNode{Type: str(m, "type"), Name: str(m, "tag"), Server: str(m, "server"), UUID: str(m, "uuid"),
			Password: str(m, "password"), Method: str(m, "method"), Flow: str(m, "flow")}
		g.Port, _ = strconv.Atoi(str(m, "server_port"))
		g.AlterID, _ = strconv.Atoi(str(m, "alter_id"))
		tls := sub(m, "tls")
		g.TLS = tls["enabled"] == true
		g.SNI, g.ALPN = str(tls, "server_name"), str(tls, "alpn")
		g.FP = str(sub(tls, "utls"), "fingerprint")
		if r := sub(tls, "reality"); r["enabled"] == true {
			g.Reality, g.PBK, g.SID = true, str(r, "public_key"), str(r, "short_id")
		}
		tr := sub(m, "transport")
		g.Net, g.Path, g.Service = str(tr, "type"), str(tr, "path"), str(tr, "service_name")
		g.Host = str(sub(tr, "headers"), "Host")
		if g.Host == "" {
			g.Host = str(tr, "host")
		}
		ob := sub(m, "obfs")
		g.ObfsType, g.ObfsPass = str(ob, "type"), str(ob, "password")
		g.WGPriv, g.WGPub, g.WGPSK = str(m, "private_key"), str(m, "peer_public_key"), str(m, "pre_shared_key")
		g.WGAddr, g.WGReserved = str(m, "local_address"), str(m, "reserved")
		g.WGMTU, _ = strconv.Atoi(str(m, "mtu"))
		if s := g.toServer(); s != nil {
			out = append(out, s)
		}
	}
	return out
}

func str2(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.Itoa(int(x))
	}
	return ""
}

// ---------- Clash / Mihomo YAML (раздел proxies:) ----------
// Небольшой разбор нужного подмножества YAML: список узлов в блочном или «{}»-виде,
// вложенные ws-opts / reality-opts / grpc-opts.
func parseClashYAML(text string) []*Server {
	lines := strings.Split(strings.ReplaceAll(text, "\r", ""), "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "proxies:") && indentOf(l) == 0 {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	var items []map[string]any
	var cur map[string]any
	var stack []struct {
		ind int
		m   map[string]any
	}
	itemInd := -1
	for _, raw := range lines[start:] {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		ind := indentOf(raw)
		if ind == 0 {
			break // следующий раздел
		}
		l := strings.TrimSpace(raw)
		if strings.HasPrefix(l, "- ") && (itemInd < 0 || ind <= itemInd) {
			itemInd = ind
			body := strings.TrimSpace(l[2:])
			cur = map[string]any{}
			items = append(items, cur)
			stack = []struct {
				ind int
				m   map[string]any
			}{{ind + 2, cur}}
			if strings.HasPrefix(body, "{") {
				for k, v := range parseFlowMap(body) {
					cur[k] = v
				}
				continue
			}
			l = body
			ind += 2
		}
		if cur == nil {
			continue
		}
		for len(stack) > 1 && ind < stack[len(stack)-1].ind {
			stack = stack[:len(stack)-1]
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		top := stack[len(stack)-1].m
		switch {
		case v == "":
			nm := map[string]any{}
			top[k] = nm
			stack = append(stack, struct {
				ind int
				m   map[string]any
			}{ind + 1, nm})
		case strings.HasPrefix(v, "{"):
			top[k] = parseFlowMap(v)
		default:
			top[k] = yamlScalar(v)
		}
	}
	var out []*Server
	for _, it := range items {
		s := func(m map[string]any, k string) string {
			if v, ok := m[k]; ok {
				switch x := v.(type) {
				case string:
					return x
				case []string:
					return strings.Join(x, ",")
				}
			}
			return ""
		}
		mm := func(m map[string]any, k string) map[string]any {
			if v, ok := m[k].(map[string]any); ok {
				return v
			}
			return map[string]any{}
		}
		g := genericNode{Type: s(it, "type"), Name: s(it, "name"), Server: s(it, "server"), UUID: s(it, "uuid"),
			Password: s(it, "password"), Method: s(it, "cipher"), Flow: s(it, "flow"), Net: s(it, "network"),
			SNI: s(it, "servername"), FP: s(it, "client-fingerprint"), ALPN: s(it, "alpn")}
		if g.SNI == "" {
			g.SNI = s(it, "sni")
		}
		g.Port, _ = strconv.Atoi(s(it, "port"))
		g.AlterID, _ = strconv.Atoi(s(it, "alterId"))
		g.TLS = s(it, "tls") == "true" || g.Type == "trojan" || g.Type == "hysteria2"
		if r := mm(it, "reality-opts"); len(r) > 0 {
			g.Reality, g.PBK, g.SID = true, s(r, "public-key"), s(r, "short-id")
		}
		ws := mm(it, "ws-opts")
		g.Path, g.Host = s(ws, "path"), s(mm(ws, "headers"), "Host")
		if hp := mm(it, "http-opts"); len(hp) > 0 && g.Path == "" {
			g.Path = s(hp, "path")
		}
		g.Service = s(mm(it, "grpc-opts"), "grpc-service-name")
		g.ObfsType, g.ObfsPass = s(it, "obfs"), s(it, "obfs-password")
		g.WGPriv, g.WGPub, g.WGPSK = s(it, "private-key"), s(it, "public-key"), s(it, "pre-shared-key")
		g.WGAddr = strings.Trim(s(it, "ip")+","+s(it, "ipv6"), ",")
		g.WGReserved = s(it, "reserved")
		g.WGMTU, _ = strconv.Atoi(s(it, "mtu"))
		if srv := g.toServer(); srv != nil {
			out = append(out, srv)
		}
	}
	return out
}

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

func yamlScalar(v string) any {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		var arr []string
		for _, p := range splitFlow(v[1 : len(v)-1]) {
			arr = append(arr, unquote(p))
		}
		return arr
	}
	return unquote(v)
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

// «{a: b, c: {d: e}, f: [x, y]}»
func parseFlowMap(s string) map[string]any {
	m := map[string]any{}
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
	for _, part := range splitFlow(s) {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		k, v = unquote(k), strings.TrimSpace(v)
		if strings.HasPrefix(v, "{") {
			m[k] = parseFlowMap(v)
		} else {
			m[k] = yamlScalar(v)
		}
	}
	return m
}

// разбить по запятым верхнего уровня (с учётом скобок и кавычек)
func splitFlow(s string) []string {
	var out []string
	depth, start := 0, 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if t := strings.TrimSpace(s[start:]); t != "" {
		out = append(out, t)
	}
	return out
}
