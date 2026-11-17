package main

import (
	"os"
	"strings"
	"testing"
)

func TestZapret(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("ZAPRET_ZIP"))
	if err != nil {
		t.Skip("no zip")
	}
	dst := t.TempDir() + "/zapret"
	v, err := extractZapretZip(data, dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("version", v)
	st := listStrategies(dst)
	t.Log(len(st), st[:4], st[len(st)-1])
	for _, s := range st {
		c, err := buildCmdline(dst, s, true)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if strings.Contains(c, "%") {
			t.Fatalf("%s leftover %%: %s", s, c)
		}
		if !strings.Contains(c, "list-vpnauto.txt") {
			t.Fatalf("%s: no vpnauto list", s)
		}
	}
	c, _ := buildCmdline(dst, "general (ALT11).bat", false)
	t.Log(c[:400])
	if !versionNewer("1.10.5", "1.10.4") || versionNewer("1.10.4", "1.10.4") || !versionNewer("1.11", "1.10.9") || !versionNewer("1.9.7b", "1.9.7") {
		t.Fatal("versions")
	}
}
