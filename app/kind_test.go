package main

import "testing"

func TestKinds(t *testing.T) {
	links := "vless://u@de.example.com:443?security=tls#🇩🇪 Германия\n" +
		"vless://u@gb.example.com:443?security=tls#🇬🇧 GB London\n" +
		"vless://u@t.example.com:443?security=tls#🇳🇱 Torrent / Торренты\n" +
		"vless://u@0.0.0.0:1?security=tls#📅 Истекает 01.12.2026\n" +
		"vless://u@i.example.com:443?security=tls#Осталось: 45 ГБ\n" +
		"vless://u@f.example.com:443?security=tls#🇫🇮 Финляндия²\n"
	s := parseBody(links)
	want := []string{"", "", "special", "info", "info", ""}
	for i, x := range s {
		if x.Kind != want[i] {
			t.Errorf("%q: got %q want %q", x.Name, x.Kind, want[i])
		}
	}
}

func TestStartServer(t *testing.T) {
	s := []*Server{{Name: "info", Kind: "info"}, {Name: "A"}, {Name: "B"}, {Name: "BY", Kind: "cis"}}
	if startServer(s, "", "B") != 2 || startServer(s, "", "") != 1 || startServer(s, "BY", "B") != 3 || startServer(s, "", "BY") != 1 || startServer(s, "", "gone") != 1 {
		t.Fatal("start server")
	}
}

func TestOEM(t *testing.T) {
	// «Ошибка: Отказано в доступе.» в CP866
	b := []byte{0x8e, 0xe8, 0xa8, 0xa1, 0xaa, 0xa0, 0x3a, 0x20, 0x8e, 0xe2, 0xaa, 0xa0, 0xa7, 0xa0, 0xad, 0xae, 0x20, 0xa2, 0x20, 0xa4, 0xae, 0xe1, 0xe2, 0xe3, 0xaf, 0xa5, 0x2e}
	if s := decodeOEM(b); s != "Ошибка: Отказано в доступе." {
		t.Fatal(s)
	}
}
