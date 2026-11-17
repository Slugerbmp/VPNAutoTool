package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const clashYAML = `port: 7890
proxies:
  - {name: "NL vless", type: vless, server: nl.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, network: tcp, tls: true, flow: xtls-rprx-vision, servername: www.microsoft.com, client-fingerprint: chrome, reality-opts: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, short-id: abcd}}
  - name: DE trojan
    type: trojan
    server: de.example.com
    port: 443
    password: secret
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: de.example.com
  - name: SS
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: pw
  - name: HY2
    type: hysteria2
    server: hy.example.com
    port: 443
    password: hypw
    obfs: salamander
    obfs-password: obfspw
proxy-groups:
  - name: auto
`

const singJSON = `{"outbounds":[
 {"type":"vless","tag":"sb-vless","server":"a.example.com","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision",
  "tls":{"enabled":true,"server_name":"www.apple.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"ab"}}},
 {"type":"vmess","tag":"sb-vmess","server":"b.example.com","server_port":8443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true},"transport":{"type":"ws","path":"/v","headers":{"Host":"b.example.com"}}},
 {"type":"hysteria2","tag":"sb-hy2","server":"c.example.com","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"c.example.com"}},
 {"type":"wireguard","tag":"sb-wg","server":"162.159.192.1","server_port":2408,"private_key":"cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=","peer_public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","local_address":["172.16.0.2/32"],"reserved":[1,2,3],"mtu":1280},
 {"type":"direct","tag":"direct"},{"type":"selector","tag":"proxy"}]}`

func TestAnySubscription(t *testing.T) {
	cases := map[string]int{
		clashYAML: 4,
		singJSON:  4,
		"hysteria2://pw@h.example.com:443?sni=h.example.com&obfs=salamander&obfs-password=x#hy\n" +
			"hy2://pw@[2001:db8::1]:8443/?insecure=1#v6\n" +
			"wireguard://cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=@162.159.192.1:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32&reserved=1,2,3#wg": 3,
		`{"version":1,"servers":[{"server":"1.1.1.1","server_port":8388,"method":"aes-256-gcm","password":"x","remarks":"sip"}]}`: 1,
	}
	xr := xrayBin()
	_, haveXray := os.Stat(xr)
	for body, want := range cases {
		s := parseBody(body)
		if len(s) != want {
			t.Fatalf("got %d servers, want %d for %.40q", len(s), want, body)
		}
		for _, sv := range s {
			if haveXray != nil {
				continue
			}
			ob := sv.Outbound
			ob["tag"] = "p"
			cfg := map[string]any{"inbounds": []any{map[string]any{"port": 47999, "listen": "127.0.0.1", "protocol": "http"}}, "outbounds": []any{ob}}
			b, _ := json.Marshal(cfg)
			f := filepath.Join(t.TempDir(), "c.json")
			os.WriteFile(f, b, 0644)
			if out, err := exec.Command(xr, "run", "-test", "-c", f).CombinedOutput(); err != nil {
				t.Errorf("%s: xray rejects: %s\n%s", sv.Name, out, b)
			}
		}
	}
}

func TestLegacyFP(t *testing.T) {
	out := string(legacyFingerprints([]byte(`{"fingerprint":"hellochrome_133","x":{"fingerprint": "chrome"},"y":{"fingerprint":"HelloFirefox_120"}}`)))
	if out != `{"fingerprint":"chrome","x":{"fingerprint": "chrome"},"y":{"fingerprint":"firefox"}}` {
		t.Fatal(out)
	}
}

func TestUpdateVersion(t *testing.T) {
	if !versionNewer("1.10.0", "1.9.1") || versionNewer("1.9.1", "1.9.1") || versionNewer("1.9.0", "1.9.1") {
		t.Fatal("ver")
	}
	m := readSums(strings.NewReader("abc123  VPN-Auto-Setup.exe\ndef *VPN-Auto-macOS.zip\n"))
	if m["VPN-Auto-Setup.exe"] != "abc123" || m["VPN-Auto-macOS.zip"] != "def" {
		t.Fatal(m)
	}
}
