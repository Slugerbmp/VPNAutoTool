package main

// «Скачать журналы»: собирает журналы и состояние в один zip в папке «Загрузки» и показывает его
// в проводнике — файл можно сразу отправить в Telegram. Ключи подписки, лицензия WARP и
// настройки серверов в архив не попадают.

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var (
	reLicense = regexp.MustCompile(`(?i)(License:\s*)\S+`)
	reSubURL  = regexp.MustCompile(`(?i)(https?://[^\s"']*?/)[A-Za-z0-9_\-]{8,}`)
	reVless   = regexp.MustCompile(`(?i)(vless|vmess|trojan|ss|hysteria2?|tuic)://\S+`)
)

func redactLog(s string) string {
	s = reLicense.ReplaceAllString(s, "${1}***")
	s = reVless.ReplaceAllString(s, "${1}://***")
	s = reSubURL.ReplaceAllString(s, "${1}***")
	return s
}

// настройки без ключей подписок
func redactedSettings() []byte {
	b, err := os.ReadFile(filepath.Join(dataDir, "settings.json"))
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return []byte(redactLog(string(b)))
	}
	if _, ok := m["key"]; ok {
		m["key"] = "***"
	}
	if ps, ok := m["profiles"].([]any); ok {
		for _, p := range ps {
			if pm, ok := p.(map[string]any); ok {
				pm["key"] = "***"
			}
		}
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	return out
}

func tailFile(p string, max int64) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, _ := f.Stat()
	if st.Size() > max {
		f.Seek(-max, 2)
	}
	b := make([]byte, max)
	n, _ := f.Read(b)
	return b[:n]
}

func downloadsDir() string {
	home, _ := os.UserHomeDir()
	d := filepath.Join(home, "Downloads")
	if st, err := os.Stat(d); err == nil && st.IsDir() {
		return d
	}
	if d, err := os.UserHomeDir(); err == nil {
		return filepath.Join(d, "Desktop")
	}
	return os.TempDir()
}

func (a *App) collectLogs() (string, error) {
	name := "NETtool-журналы-" + time.Now().Format("2006-01-02_15-04") + ".zip"
	out := filepath.Join(downloadsDir(), name)
	f, err := os.Create(out)
	if err != nil {
		return "", err
	}
	zw := zip.NewWriter(f)
	add := func(n string, b []byte) {
		if len(b) == 0 {
			return
		}
		w, err := zw.Create(n)
		if err == nil {
			w.Write(b)
		}
	}
	for _, n := range []string{"app.log", "zapret.log", "zapret-task.log", "gateway.log"} {
		add(n, []byte(redactLog(string(tailFile(filepath.Join(dataDir, n), 2<<20)))))
	}
	add("core.log", []byte(redactLog(string(tailFile(filepath.Join(dataDir, "core.log"), 300<<10)))))
	for _, n := range []string{"gateway.json", "gateway-state.json", "zapret-state.json", "zapret-cmd.json", "gateway-fwd.txt"} {
		b, _ := os.ReadFile(filepath.Join(dataDir, n))
		add(n, []byte(redactLog(string(b))))
	}
	add("settings.json", redactedSettings())

	a.mu.Lock()
	info := fmt.Sprintf("NETtool %s\nОС: %s/%s\nВремя: %s\nРежим: %s, VPN включён: %v\n",
		appVersion, runtime.GOOS, runtime.GOARCH, time.Now().Format(time.RFC3339), a.settings.Mode, a.on)
	if a.cur >= 0 && a.cur < len(a.servers) {
		info += "Сервер: " + a.servers[a.cur].Name + "\n"
	}
	a.mu.Unlock()
	info += fmt.Sprintf("Запрет запущен: %v\n", zapretSupported && winwsRunning())
	add("сведения.txt", []byte(info))
	if runtime.GOOS == "windows" {
		var sb strings.Builder
		run := func(title, name string, args ...string) {
			o, _ := hiddenCmd(name, args...).CombinedOutput()
			sb.WriteString("===== " + title + " =====\n" + decodeOEM(o) + "\n")
		}
		run("ipconfig /all", "ipconfig", "/all")
		run("route print -4", "route", "print", "-4")
		run("Адаптеры и пересылка", "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-NetIPInterface -AddressFamily IPv4 | Format-Table ifIndex,InterfaceAlias,Forwarding,ConnectionState,InterfaceMetric -AutoSize | Out-String -Width 200")
		add("сеть.txt", []byte(sb.String()))
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	return out, nil
}

func showInFolder(p string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("explorer", "/select,", p).Start()
	case "darwin":
		exec.Command("open", "-R", p).Start()
	}
}

func (a *App) logsRoutes(m *http.ServeMux) {
	m.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		p, err := a.collectLogs()
		if err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		showInFolder(p)
		writeJSON(w, map[string]any{"ok": true, "path": p})
	})
}
