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
