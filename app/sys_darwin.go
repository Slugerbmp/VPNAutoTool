//go:build darwin

package main

// macOS: прокси через networksetup, диалоги через osascript, самоустановка в /Applications.

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

const coreName = "vpnauto-core"

func defaultDataDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "Library", "Application Support", "VPNAuto")
}

func xrayURL() string {
	if runtime.GOARCH == "arm64" {
		return "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-arm64-v8a.zip"
	}
	return "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-64.zip"
}

func browserPaths() []string {
	return []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		"/Applications/Yandex.app/Contents/MacOS/Yandex",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	}
}

func detach(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

func hiddenCmd(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }

func openURL(u string) { exec.Command("open", u).Start() }

func killProcess(name string) { exec.Command("pkill", "-x", name).Run() }

func uninstall() {}

// ---------- диалоги ----------
func asStr(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Повторяет поведение MessageBox из Windows-версии: 0x4 — кнопки Да/Нет (вернёт 6 при «Да»).
func msgBox(text string, flags uintptr) int {
	icon := "note"
	if flags&0x10 != 0 {
		icon = "stop"
	} else if flags&0x30 == 0x30 {
		icon = "caution"
	}
	buttons := `buttons {"OK"} default button "OK"`
	if flags&0x4 != 0 {
		buttons = `buttons {"Нет", "Да"} default button "Да"`
	}
	script := fmt.Sprintf(`display dialog %s with title "NETtool" %s with icon %s`, asStr(text), buttons, icon)
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return 7
	}
	if strings.Contains(string(out), "Да") {
		return 6
	}
	return 1
}

func askButtons(text string, buttons ...string) string {
	q := make([]string, len(buttons))
	for i, b := range buttons {
		q[i] = asStr(b)
	}
	script := fmt.Sprintf(`display dialog %s with title "NETtool" buttons {%s} default button %s with icon note`,
		asStr(text), strings.Join(q, ", "), q[len(q)-1])
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	return strings.TrimPrefix(s, "button returned:")
}

// Выполнить shell-команды; при нехватке прав — один раз спросить пароль администратора.
func runShell(lines []string, prompt string) error {
	script := "set -e\n" + strings.Join(lines, "\n") + "\n"
	if out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput(); err == nil && !strings.Contains(string(out), "Error") {
		return nil
	} else {
		log.Printf("без прав не вышло: %v %s", err, out)
	}
	f := filepath.Join(dataDir, "admin-task.sh")
	if err := os.WriteFile(f, []byte(script), 0700); err != nil {
		return err
	}
	defer os.Remove(f)
	as := fmt.Sprintf(`do shell script "/bin/sh " & quoted form of %s with administrator privileges with prompt %s`, asStr(f), asStr(prompt))
	if out, err := exec.Command("osascript", "-e", as).CombinedOutput(); err != nil {
		return fmt.Errorf("не удалось изменить настройки: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ---------- системный прокси ----------
func networkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var res []string
	for i, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if i == 0 || l == "" || strings.HasPrefix(l, "*") {
			continue
		}
		res = append(res, l)
	}
	return res
}

func setSysProxy(on bool) error {
	host, port, _ := strings.Cut(proxyAddr, ":")
	var lines []string
	for _, s := range networkServices() {
		q := shq(s)
		if on {
			lines = append(lines,
				"networksetup -setwebproxy "+q+" "+host+" "+port,
				"networksetup -setsecurewebproxy "+q+" "+host+" "+port,
				"networksetup -setproxybypassdomains "+q+" localhost 127.0.0.1 '*.local' 169.254/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"+macBypass(),
				"networksetup -setwebproxystate "+q+" on",
				"networksetup -setsecurewebproxystate "+q+" on")
		} else {
			lines = append(lines,
				"networksetup -setwebproxystate "+q+" off",
				"networksetup -setsecurewebproxystate "+q+" off")
		}
	}
	if len(lines) == 0 {
		return fmt.Errorf("не найдено сетевых подключений")
	}
	prompt := "NETtool хочет включить VPN (изменить настройки прокси)."
	if !on {
		prompt = "NETtool хочет выключить VPN (вернуть настройки прокси)."
	}
	return runShell(lines, prompt)
}

func cleanupStaleProxy() {
	_, port, _ := strings.Cut(proxyAddr, ":")
	for _, s := range networkServices() {
		out, _ := exec.Command("networksetup", "-getwebproxy", s).Output()
		o := string(out)
		if strings.Contains(o, "Enabled: Yes") && strings.Contains(o, "Port: "+port) {
			setSysProxy(false)
			return
		}
	}
}

// ---------- установка в «Программы» ----------
const appBundleDst = "/Applications/NETtool.app"

func selfInstall() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	i := strings.Index(exe, ".app/Contents/MacOS/")
	if i < 0 {
		return false
	}
	bundle := exe[:i+4]
	if bundle == appBundleDst || strings.HasPrefix(bundle, "/Applications/") {
		return false
	}
	marker := filepath.Join(dataDir, "no-install")
	if _, err := os.Stat(marker); err == nil {
		return false
	}

	_, existsErr := os.Stat(appBundleDst)
	updating := existsErr == nil
	text := "Установить NETtool в папку «Программы»?"
	btn := "Установить"
	if updating {
		text = "В «Программах» уже есть NETtool. Обновить его до версии " + appVersion + "?"
		btn = "Обновить"
	}
	ans := askButtons(text, "Не устанавливать", btn)
	if ans == "" {
		return true // закрыли окно — просто выходим
	}
	if ans != btn {
		os.WriteFile(marker, []byte("1"), 0644)
		return false
	}
	addDock := askButtons("Добавить значок NETtool в Dock?", "Нет", "Добавить") == "Добавить"

	// закрываем уже установленную копию, если она запущена
	exec.Command("pkill", "-f", "^/Applications/NETtool.app/Contents/MacOS/").Run()
	exec.Command("pkill", "-f", "^/Applications/VPN Auto.app/Contents/MacOS/").Run() // прежнее название
	killProcess(coreName)

	lines := []string{
		"rm -rf " + shq(appBundleDst),
		"rm -rf '/Applications/VPN Auto.app'", // прежнее название программы
		"ditto " + shq(bundle) + " " + shq(appBundleDst),
		"xattr -dr com.apple.quarantine " + shq(appBundleDst) + " || true",
	}
	if err := runShell(lines, "NETtool хочет установить себя в папку «Программы»."); err != nil {
		msgBox("Не удалось установить: "+err.Error(), 0x10)
		return false
	}
	if addDock {
		out, _ := exec.Command("defaults", "read", "com.apple.dock", "persistent-apps").Output()
		if !strings.Contains(string(out), "NETtool.app") {
			exec.Command("defaults", "write", "com.apple.dock", "persistent-apps", "-array-add",
				`<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>file:///Applications/NETtool.app/</string><key>_CFURLStringType</key><integer>15</integer></dict></dict></dict>`).Run()
			exec.Command("killall", "Dock").Run()
		}
	}
	exec.Command("open", "-n", appBundleDst).Start()
	return true
}

func macBypass() string {
	s := ""
	for _, d := range bypassList {
		s += " " + shq("*."+d) + " " + shq(d)
	}
	return s
}

func fetchSystem(u, ua string) (string, error) {
	out, err := exec.Command("curl", "-fsSL", "--max-time", "30", "-A", ua, u).Output()
	if err != nil {
		return "", fmt.Errorf("curl: %v", err)
	}
	return string(out), nil
}

func openFolder(p string) { exec.Command("open", p).Start() }

const hotkeySupported = false

func hotkeySet(bool) {}
func openMini()      { openUI() }

func notify(title, text string) {
	exec.Command("osascript", "-e", fmt.Sprintf(`display notification %s with title %s`, asStr(text), asStr(title))).Start()
}

func launchAgentPath() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "Library", "LaunchAgents", "app.vpnauto.plist")
}

func setAutostart(on bool) error {
	p := launchAgentPath()
	if !on {
		os.Remove(p)
		return nil
	}
	exe, _ := os.Executable()
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>app.vpnauto</string>
<key>ProgramArguments</key><array><string>` + exe + `</string><string>--autostart</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`
	os.MkdirAll(filepath.Dir(p), 0755)
	return os.WriteFile(p, []byte(plist), 0644)
}

func currentNetwork() string {
	for _, dev := range []string{"en0", "en1"} {
		out, _ := exec.Command("networksetup", "-getairportnetwork", dev).Output()
		s := strings.TrimSpace(string(out))
		if i := strings.Index(s, ": "); i >= 0 && strings.HasPrefix(s, "Current") {
			return s[i+2:]
		}
	}
	return ""
}
