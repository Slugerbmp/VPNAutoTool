//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const internetSettings = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var (
	wininet       = syscall.NewLazyDLL("wininet.dll")
	procInetSetOp = wininet.NewProc("InternetSetOptionW")
	user32        = syscall.NewLazyDLL("user32.dll")
	procMsgBox    = user32.NewProc("MessageBoxW")
)

func hiddenCmd(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return c
}

func setSysProxy(on bool) error {
	var err error
	if on {
		if err = hiddenCmd("reg", "add", internetSettings, "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyAddr, "/f").Run(); err != nil {
			return fmt.Errorf("не удалось включить системный прокси: %v", err)
		}
		hiddenCmd("reg", "add", internetSettings, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "localhost;127.*;10.*;172.16.*;192.168.*"+bypassProxyOverride()+";<local>", "/f").Run()
		err = hiddenCmd("reg", "add", internetSettings, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f").Run()
	} else {
		err = hiddenCmd("reg", "add", internetSettings, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f").Run()
	}
	procInetSetOp.Call(0, 39, 0, 0) // SETTINGS_CHANGED
	procInetSetOp.Call(0, 37, 0, 0) // REFRESH
	return err
}

// Если прошлый запуск закрылся аварийно и оставил наш прокси — снимаем его.
func cleanupStaleProxy() {
	out, _ := hiddenCmd("reg", "query", internetSettings, "/v", "ProxyServer").Output()
	if strings.Contains(string(out), proxyAddr) {
		setSysProxy(false)
	}
}

func killProcess(image string) {
	hiddenCmd("taskkill", "/F", "/IM", image).Run()
}

func openURL(u string) {
	hiddenCmd("rundll32", "url.dll,FileProtocolHandler", u).Start()
}

func msgBox(text string, flags uintptr) int {
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString("NETtool")
	r, _, _ := procMsgBox.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), flags)
	return int(r)
}

func uninstall() {
	if msgBox("Удалить NETtool с этого компьютера?", 0x4|0x20) != 6 {
		return
	}
	if zapretTaskExists() {
		// остановить запрет и удалить задачу (удаление требует прав администратора)
		zapretRun(zCmd{Action: "stop"}, 10*time.Second)
		hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command",
			`Start-Process schtasks -ArgumentList '/delete','/tn','VPNAuto\Zapret','/f' -Verb RunAs -WindowStyle Hidden -Wait`).Run()
	}
	hiddenCmd("taskkill", "/F", "/IM", "VPNAuto.exe", "/FI", fmt.Sprintf("PID ne %d", os.Getpid())).Run()
	killProcess(coreName)
	cleanupStaleProxy()
	setAutostart(false)
	ps := `$d=[Environment]::GetFolderPath('Desktop'); $p=[Environment]::GetFolderPath('Programs');` +
		`foreach($n in 'NETtool.lnk','VPN Auto.lnk'){` +
		`Remove-Item -LiteralPath (Join-Path $d $n) -ErrorAction SilentlyContinue;` +
		`Remove-Item -LiteralPath (Join-Path $p $n) -ErrorAction SilentlyContinue}`
	hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
	hiddenCmd("reg", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNAuto`, "/f").Run()
	os.RemoveAll(dataDir)

	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	if b := filepath.Base(dir); !strings.EqualFold(b, "NETtool") && !strings.EqualFold(b, "VPN Auto") {
		// программа лежит не в своей папке — удаляем только свои файлы
		if m, _ := filepath.Glob(filepath.Join(dir, "icon*.ico")); len(m) > 0 {
			for _, f := range m {
				os.Remove(f)
			}
		}
		c := exec.Command("cmd")
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000,
			CmdLine: fmt.Sprintf(`cmd /c ping 127.0.0.1 -n 3 >nul & del /f /q "%s"`, exe)}
		c.Start()
		msgBox("NETtool удалён.", 0x40)
		return
	}
	c := exec.Command("cmd")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000,
		CmdLine: fmt.Sprintf(`cmd /c ping 127.0.0.1 -n 3 >nul & rmdir /s /q "%s"`, dir)}
	c.Start()
	msgBox("NETtool удалён.", 0x40)
}

const coreName = "vpnauto-core.exe"

func defaultDataDir() string {
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		return filepath.Join(d, "VPNAuto")
	}
	return filepath.Join(os.TempDir(), "VPNAuto")
}

func xrayURL() string {
	return "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
}

func browserPaths() []string {
	return []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Google\Chrome\Application\chrome.exe`),
	}
}

func selfInstall() bool { return false }
func detach(*exec.Cmd)  {}

// Загрузка через PowerShell: другой TLS-стек (как у Happ и браузеров) и системный прокси.
func fetchSystem(u, ua string) (string, error) {
	f := filepath.Join(os.TempDir(), fmt.Sprintf("vpnauto-sub-%d.txt", time.Now().UnixNano()))
	defer os.Remove(f)
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	ps := "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; " +
		"Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -Uri " + q(u) + " -UserAgent " + q(ua) + " -OutFile " + q(f)
	out, err := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("системная загрузка: %s", lastLines(string(out), 2))
	}
	b, err := os.ReadFile(f)
	return string(b), err
}

func openFolder(p string) { exec.Command("explorer", p).Start() }

const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

func setAutostart(on bool) error {
	hiddenCmd("reg", "delete", runKey, "/v", "VPN Auto", "/f").Run() // прежнее название
	if !on {
		hiddenCmd("reg", "delete", runKey, "/v", "NETtool", "/f").Run()
		return nil
	}
	exe, _ := os.Executable()
	if out, err := hiddenCmd("reg", "add", runKey, "/v", "NETtool", "/t", "REG_SZ", "/d", `"`+exe+`" --autostart`, "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("автозапуск: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Имя текущей сети (SSID для Wi-Fi или имя сетевого профиля для провода).
func currentNetwork() string {
	ps := `[Console]::OutputEncoding=[Text.Encoding]::UTF8; ` +
		`(Get-NetConnectionProfile | Where-Object { $_.InterfaceAlias -notmatch 'WARP|Wintun|vEthernet|Loopback' -and ($_.IPv4Connectivity -eq 'Internet' -or $_.IPv6Connectivity -eq 'Internet') } | Sort-Object InterfaceIndex | Select-Object -First 1).Name`
	out, err := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Быстрая проверка, запущен ли процесс (без запуска tasklist).
func processRunning(image string) bool {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if syscall.Process32First(snap, &e) != nil {
		return false
	}
	for {
		if strings.EqualFold(syscall.UTF16ToString(e.ExeFile[:]), image) {
			return true
		}
		if syscall.Process32Next(snap, &e) != nil {
			return false
		}
	}
}
