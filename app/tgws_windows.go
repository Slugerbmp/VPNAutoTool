//go:build windows

package main

// TG WS Proxy (github.com/Flowseal/tg-ws-proxy): локальный прокси для Telegram Desktop,
// который пускает трафик Telegram через WebSocket. Скачиваем последнюю версию с GitHub,
// запускаем/останавливаем, обновляем и подключаем Telegram по ссылке tg://proxy.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const tgwsSupported = true
const tgwsRepo = "Flowseal/tg-ws-proxy"
const tgwsExeName = "TgWsProxy.exe"

func tgwsDir() string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "tgwsproxy")
}

func tgwsExe() string     { return filepath.Join(tgwsDir(), tgwsExeName) }
func tgwsInstalled() bool { _, err := os.Stat(tgwsExe()); return err == nil }
func tgwsLocalVersion() string {
	b, _ := os.ReadFile(filepath.Join(tgwsDir(), "version.txt"))
	return strings.TrimSpace(string(b))
}

func tgwsRunning() bool {
	return processRunning(tgwsExeName)
}

type ghRelease struct {
	Tag    string `json:"tag_name"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func tgwsLatest() (ghRelease, error) {
	var rel ghRelease
	cl := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+tgwsRepo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := cl.Do(req)
	if err != nil {
		return rel, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return rel, fmt.Errorf("GitHub ответил %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&rel)
	return rel, err
}

// Скачать и поставить (или обновить) TG WS Proxy. Права администратора не нужны.
func tgwsInstall() (string, error) {
	rel, err := tgwsLatest()
	if err != nil {
		return "", fmt.Errorf("не удалось узнать последнюю версию TG WS Proxy: %v", err)
	}
	want := "TgWsProxy_windows.exe"
	if runtime.GOARCH == "arm64" {
		want = "TgWsProxy_windows_arm64.exe"
	}
	u := ""
	for _, a := range rel.Assets {
		if strings.EqualFold(a.Name, want) {
			u = a.URL
		}
	}
	if u == "" {
		return "", errors.New("в релизе TG WS Proxy нет файла " + want)
	}
	cl := &http.Client{Timeout: 10 * time.Minute}
	resp, err := cl.Get(u)
	if err != nil {
		return "", fmt.Errorf("скачивание TG WS Proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("скачивание TG WS Proxy: ответ %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	was := tgwsRunning()
	tgwsStop()
	os.MkdirAll(tgwsDir(), 0755)
	tmp := tgwsExe() + ".new"
	if err := os.WriteFile(tmp, data, 0755); err != nil {
		return "", err
	}
	os.Remove(tgwsExe())
	if err := os.Rename(tmp, tgwsExe()); err != nil {
		return "", err
	}
	os.WriteFile(filepath.Join(tgwsDir(), "version.txt"), []byte(rel.Tag), 0644)
	if was {
		tgwsStart()
	}
	return rel.Tag, nil
}

func tgwsStart() error {
	if !tgwsInstalled() {
		return errors.New("TG WS Proxy не установлен")
	}
	if tgwsRunning() {
		return nil
	}
	cmd := exec.Command(tgwsExe())
	cmd.Dir = tgwsDir()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("не удалось запустить TG WS Proxy: %v", err)
	}
	go cmd.Wait()
	for i := 0; i < 20 && !tgwsRunning(); i++ {
		time.Sleep(250 * time.Millisecond)
	}
	if !tgwsRunning() {
		return errors.New("TG WS Proxy сразу закрылся — возможно, его удалил антивирус")
	}
	return nil
}

func tgwsStop() {
	hiddenCmd("taskkill", "/F", "/IM", tgwsExeName).Run()
}

// Ссылка для Telegram Desktop по настройкам TG WS Proxy (%APPDATA%\TgWsProxy\config.json).
func tgwsLink() string {
	host, port, secret := "127.0.0.1", "1443", ""
	b, err := os.ReadFile(filepath.Join(os.Getenv("APPDATA"), "TgWsProxy", "config.json"))
	if err == nil {
		var cfg map[string]any
		if json.Unmarshal(b, &cfg) == nil {
			str := func(k string) string {
				if v, ok := cfg[k]; ok && v != nil {
					s := fmt.Sprint(v)
					if f, ok := v.(float64); ok {
						s = fmt.Sprintf("%.0f", f)
					}
					return s
				}
				return ""
			}
			if v := str("port"); v != "" {
				port = v
			}
			if v := str("host"); v != "" && v != "0.0.0.0" {
				host = v
			}
			secret = str("secret")
		}
	}
	if secret == "" {
		// старые версии — SOCKS5 без секрета
		if port == "1443" {
			port = "1080"
		}
		return fmt.Sprintf("tg://socks?server=%s&port=%s", host, port)
	}
	return fmt.Sprintf("tg://proxy?server=%s&port=%s&secret=%s", host, port, secret)
}

func tgwsLatestTag() (string, error) {
	r, err := tgwsLatest()
	return r.Tag, err
}
