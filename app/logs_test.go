package main

import (
	"strings"
	"testing"
)

func TestRedactLog(t *testing.T) {
	in := "License: AAAA1111-BBBB2222-CCCC3333\nsub https://example.test/FakeKey1234567 ok\nvless://someuuid@host:443?x=1 end"
	out := redactLog(in)
	for _, bad := range []string{"AAAA1111", "FakeKey1234567", "someuuid@host"} {
		if strings.Contains(out, bad) {
			t.Fatalf("не скрыто %q: %s", bad, out)
		}
	}
}
