package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestUpdateFlow(t *testing.T) {
	payload := []byte("fake installer")
	sum := sha256.Sum256(payload)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			fmt.Fprintf(w, `{"tag_name":"v99.0.0","html_url":"x","assets":[{"name":"NETtool-Setup.exe","browser_download_url":"%[1]s/a"},{"name":"NETtool-macOS.zip","browser_download_url":"%[1]s/a"},{"name":"SHA256SUMS.txt","browser_download_url":"%[1]s/s"}]}`, srv.URL)
		case r.URL.Path == "/a":
			w.Write(payload)
		case r.URL.Path == "/s":
			fmt.Fprintf(w, "%s  NETtool-Setup.exe\n%s  NETtool-macOS.zip\n", hex.EncodeToString(sum[:]), hex.EncodeToString(sum[:]))
		}
	}))
	defer srv.Close()
	updateAPI = srv.URL
	dataDir = t.TempDir()
	a := &App{cur: -1}
	if err := a.checkUpdate(); err != nil {
		t.Fatal(err)
	}
	if v, ok := updAvailable(); !ok || v != "99.0.0" {
		t.Fatal(v, ok)
	}
	err := a.installUpdate() // на linux установка не поддерживается — но скачивание и проверка суммы должны пройти
	if err == nil || !strings.Contains(err.Error(), "только для Windows") {
		t.Fatal("expected platform error after verified download, got", err)
	}
	if _, e := os.Stat(dataDir + "/update/NETtool-Setup.exe"); e != nil {
		t.Fatal("not downloaded")
	}
}
