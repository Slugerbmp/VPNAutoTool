package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "VM DE", "add": "1.2.3.4", "port": 443, "id": "uuid-vm", "aid": "0", "net": "ws", "host": "h.com", "path": "/ws", "tls": "tls", "sni": "s.com"})
	ssUser := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pa:ss"))
	links := strings.Join([]string{
		"vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?type=tcp&security=reality&pbk=AbC-dEf_123&sid=ab12&sni=www.google.com&fp=chrome&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20Нидерланды",
		"vless://uuid2@[2001:db8::1]:8443?type=xhttp&security=tls&path=%2Fx%2Bp&mode=packet-up&sni=x.com#IPv6",
		"vless://uuid3@g.example.com:443?type=grpc&serviceName=svc&mode=multi&security=tls#gRPC",
		"trojan://p%40ss@t.example.com:443?sni=t.example.com#Trojan",
		"vmess://" + base64.StdEncoding.EncodeToString(vm),
		"ss://" + ssUser + "@5.6.7.8:8388#SS",
		"tuic://x@h:1#unsupported",
	}, "\n")
	sub := base64.StdEncoding.EncodeToString([]byte(links))
	servers := parseBody(sub)
	if len(servers) != 6 {
		t.Fatalf("want 6 got %d", len(servers))
	}
	for _, s := range servers {
		b, _ := json.Marshal(s.Outbound)
		t.Logf("%s => %s", s.Name, b)
	}
	if servers[0].Name != "🇳🇱 Нидерланды" {
		t.Fatal(servers[0].Name)
	}
	if !strings.Contains(string(mustJSON(servers[1].Outbound)), `"/x+p"`) {
		t.Fatal("plus lost")
	}
	if servers[3].Outbound["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)["password"] != "p@ss" {
		t.Fatal("trojan pass")
	}
	cfg := buildConfig(servers, true)
	var x map[string]any
	if err := json.Unmarshal(cfg, &x); err != nil {
		t.Fatal(err)
	}

	// JSON-подписка
	js := `[{"remarks":"J1","outbounds":[{"tag":"proxy","protocol":"vless","settings":{},"streamSettings":{"sockopt":{"dialerProxy":"frag"}}},{"tag":"direct","protocol":"freedom"}]}]`
	j := parseBody(js)
	if len(j) != 1 || j[0].Name != "J1" || strings.Contains(string(mustJSON(j[0].Outbound)), "dialerProxy") {
		t.Fatal("json sub")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
