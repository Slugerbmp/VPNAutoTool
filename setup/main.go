//go:build windows

package main

// Установщик NETtool: окно с выбором папки и галочками, ярлыки,
// регистрация в «Установке и удалении программ». Повторный запуск обновляет программу.
// Права администратора не нужны (если не выбрать системную папку).

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

//go:embed VPNAuto.exe
var appExe []byte

//go:embed icon.ico
var appIcon []byte

//go:embed dialog.ps1
var dialogPS string

const version = "1.12.6"
const uninstKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNAuto`

var procMsgBox = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")

func msgBox(text string, flags uintptr) int {
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString("Установка NETtool")
	r, _, _ := procMsgBox.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), flags)
	return int(r)
}

func hidden(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return c
}

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[2*i], b[2*i+1] = byte(v), byte(v>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func runPS(script string) ([]byte, error) {
	return hidden("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePS(script)).Output()
}

func existingInstall() string {
	out, err := hidden("reg", "query", uninstKey, "/v", "InstallLocation").Output()
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(out), "\n") {
		if i := strings.Index(l, "REG_SZ"); i >= 0 {
			return strings.TrimSpace(l[i+len("REG_SZ"):])
		}
	}
	return ""
}

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	pGetDriveType   = kernel32.NewProc("GetDriveTypeW")
	pQueryDosDevice = kernel32.NewProc("QueryDosDeviceW")
)

// Папка на обычном локальном диске? Сетевые, съёмные и виртуальные (subst) диски не годятся:
// их не видят процессы с правами администратора (задача запрета не запустится),
// а меню «Пуск» не показывает программы с таких дисков.
func localFixed(path string) bool {
	vol := filepath.VolumeName(path)
	if len(vol) != 2 || vol[1] != ':' {
		return false // \\server\share и т.п.
	}
	root, _ := syscall.UTF16PtrFromString(vol + `\`)
	if t, _, _ := pGetDriveType.Call(uintptr(unsafe.Pointer(root))); t != 3 { // DRIVE_FIXED
		return false
	}
	name, _ := syscall.UTF16PtrFromString(vol)
	buf := make([]uint16, 1024)
	if n, _, _ := pQueryDosDevice.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&buf[0])), 1024); n > 0 {
		if strings.HasPrefix(syscall.UTF16ToString(buf), `\??\`) { // subst
			return false
		}
	}
	return true
}

// Скопировать папку (запрет, TG WS Proxy) при переносе программы на другой диск.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(t, 0755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(t, b, fi.Mode())
	})
}

func desktopShortcutExists() bool {
	out, _ := runPS(`$d=[Environment]::GetFolderPath('Desktop'); (Test-Path -LiteralPath (Join-Path $d 'NETtool.lnk')) -or (Test-Path -LiteralPath (Join-Path $d 'VPN Auto.lnk'))`)
	return strings.Contains(string(out), "True")
}

func main() {
	defDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "NETtool")
	old := existingInstall()
	updating := old != ""
	if updating && localFixed(old) {
		defDir = old
	}
	// прежняя установка на сетевом/виртуальном диске — переносим на C: (см. localFixed)

	tmp, _ := os.MkdirTemp("", "vpnauto-setup")
	defer os.RemoveAll(tmp)
	tmpIco := filepath.Join(tmp, "icon.ico")
	os.WriteFile(tmpIco, appIcon, 0644)
	outFile := filepath.Join(tmp, "choice.txt")

	desk := "1"
	if updating && !desktopShortcutExists() {
		desk = "0"
	}
	mode, btn := "Автоматический выбор самого быстрого VPN-сервера", "Установить"
	if updating {
		mode, btn = "Будет обновлена установленная версия до "+version, "Обновить"
	}

	zap := "0"
	if _, err := os.Stat(filepath.Join(defDir, "zapret", "bin", "winws.exe")); err == nil {
		zap = "1"
	}
	warpInstalled := fileExists(filepath.Join(os.Getenv("ProgramFiles"), `Cloudflare\Cloudflare WARP\warp-cli.exe`))
	warpDef := "0"
	if warpInstalled {
		warpDef = "1"
	}
	tgDef := "0"
	if fileExists(filepath.Join(defDir, "tgwsproxy", "TgWsProxy.exe")) {
		tgDef = "1"
	}
	wantTg, wantAuto := false, true
	wantDef := false // исключения Защитника — по галочке в окне установщика (при тихом обновлении программа обновит их сама)
	dir, wantDesk, wantRun, wantZap, wantWarp := defDir, true, true, zap == "1", false
	// --silent: автообновление из программы — без окна, с текущими настройками,
	// без запросов прав администратора (запрет, WARP и TG WS Proxy уже стоят и обновляются сами)
	silent := len(os.Args) > 1 && os.Args[1] == "--silent"
	if silent {
		wantDesk, wantZap, wantWarp, wantTg = desk == "1", false, false, false
	} else {
		cmd := exec.Command("powershell", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePS(dialogPS))
		// только без консоли; HideWindow тут нельзя — Windows спрятала бы и само окно установщика
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
		cmd.Env = append(os.Environ(), "VA_VER="+version, "VA_ICO="+tmpIco, "VA_DIR="+defDir, "VA_DESK="+desk,
			"VA_OUT="+outFile, "VA_MODE="+mode, "VA_BTN="+btn, "VA_ZAP="+zap, "VA_WARP="+warpDef, "VA_TG="+tgDef, "VA_DEF=1")
		if err := cmd.Run(); err != nil {
			// окно не открылось — упрощённый вариант
			if msgBox(btn+" NETtool "+version+"?\n\nПапка: "+defDir, 0x4|0x20) != 6 {
				return
			}
		} else {
			b, err := os.ReadFile(outFile)
			if err != nil {
				return // нажали «Отмена» / закрыли окно
			}
			lines := strings.Split(strings.ReplaceAll(strings.TrimPrefix(string(b), "\xef\xbb\xbf"), "\r", ""), "\n")
			if len(lines) < 3 || strings.TrimSpace(lines[0]) == "" {
				return
			}
			dir = filepath.Clean(strings.TrimSpace(lines[0]))
			wantDesk = strings.TrimSpace(lines[1]) == "1"
			wantRun = strings.TrimSpace(lines[2]) == "1"
			wantZap = len(lines) > 3 && strings.TrimSpace(lines[3]) == "1"
			wantWarp = len(lines) > 4 && strings.TrimSpace(lines[4]) == "1"
			wantTg = len(lines) > 5 && strings.TrimSpace(lines[5]) == "1"
			wantAuto = len(lines) > 6 && strings.TrimSpace(lines[6]) == "1"
			wantDef = len(lines) > 7 && strings.TrimSpace(lines[7]) == "1"
			if wantWarp {
				wantZap = true
			}
		}
	}
	if !localFixed(dir) {
		alt := filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "NETtool")
		if silent || msgBox("Папка «"+dir+"» — на сетевом или виртуальном диске.\n\nОттуда не работают запрет (Windows не даёт запускать его с правами администратора) "+
			"и значок в меню «Пуск».\n\nУстановить в "+alt+"?", 0x4|0x30) == 6 {
			dir = alt
		}
	}
	// своя отдельная папка — чтобы удаление ничего лишнего не задело
	// (при обновлении остаётся прежняя «VPN Auto»: там запрет и задача планировщика)
	if b := filepath.Base(dir); !strings.EqualFold(b, "NETtool") && !strings.EqualFold(b, "VPN Auto") {
		dir = filepath.Join(dir, "NETtool")
	}
	exe := filepath.Join(dir, "VPNAuto.exe")
	// Значок — отдельным файлом с постоянным именем в папке данных на диске C:
	// (папка программы может быть на сетевом/съёмном диске, оттуда «Пуск» значки не берёт;
	// постоянное имя — чтобы закреплённые ярлыки не теряли значок после обновлений)
	icoDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "VPNAuto")
	os.MkdirAll(icoDir, 0755)
	ico := filepath.Join(icoDir, "NETtool.ico")
	os.WriteFile(ico, appIcon, 0644)

	// закрываем запущенную программу, чтобы заменить файл
	dd := filepath.Join(os.Getenv("LOCALAPPDATA"), "VPNAuto")
	// процесс шлюза запущен с правами администратора и taskkill его не закроет —
	// просим его завершиться самого (он следит за этим файлом каждую секунду)
	os.WriteFile(filepath.Join(dd, "gateway.json"), []byte(`{"on":false,"ts":0}`), 0644)
	hidden("taskkill", "/F", "/IM", "VPNAuto.exe").Run()
	hidden("taskkill", "/F", "/IM", "vpnauto-core.exe").Run()
	time.Sleep(1500 * time.Millisecond)

	if err := os.MkdirAll(dir, 0755); err != nil {
		fail(dir, err)
		return
	}
	var err error
	renamed := "" // старая копия, отодвинутая в сторону (на случай, если новую записать не выйдет)
	for i := 0; i < 6; i++ {
		if err = os.WriteFile(exe, appExe, 0755); err == nil {
			break
		}
		// файл занят запущенной копией: запущенный exe нельзя перезаписать, но можно переименовать
		if i >= 1 && renamed == "" {
			old := filepath.Join(dir, fmt.Sprintf("VPNAuto.old-%d.exe", time.Now().UnixNano()))
			if os.Rename(exe, old) == nil {
				renamed = old
				continue
			}
		}
		time.Sleep(time.Second)
	}
	if err != nil && renamed != "" {
		os.Rename(renamed, exe) // новую записать не удалось — возвращаем старую, чтобы программа не пропала
		renamed = ""
	}
	if err == nil && renamed != "" {
		hidden("cmd", "/c", "ping -n 30 127.0.0.1 >nul & del /f /q \""+renamed+"\"").Start() // убрать позже
	}
	if err == nil {
		// антивирус может удалить файл сразу после записи — тогда ярлыки остаются без значка
		time.Sleep(1500 * time.Millisecond)
		if !fileExists(exe) {
			msgBox("Антивирус удалил файл программы сразу после установки (ложное срабатывание).\n\n"+
				"Откройте «Безопасность Windows» → «Защита от вирусов и угроз» → «Журнал защиты», восстановите VPNAuto.exe "+
				"и добавьте папку\n"+dir+"\nв исключения («Управление настройками» → «Исключения»). Затем запустите установку ещё раз.", 0x30)
			return
		}
	}
	if err != nil {
		fail(dir, err)
		return
	}
	if olds, _ := filepath.Glob(filepath.Join(dir, "icon*.ico")); len(olds) > 0 {
		for _, o := range olds {
			os.Remove(o)
		}
	}

	// старая копия в другой папке больше не нужна
	if updating && !strings.EqualFold(filepath.Clean(old), filepath.Clean(dir)) {
		// перенос: запрет и TG WS Proxy — в новую папку; задачу запрета пересоздаём под новый путь
		for _, sub := range []string{"zapret", "tgwsproxy"} {
			src, dst := filepath.Join(old, sub), filepath.Join(dir, sub)
			if fileExists(src) && !fileExists(dst) {
				if copyDir(src, dst) == nil {
					os.RemoveAll(src)
					if sub == "zapret" {
						wantZap = true // заново создать задачу запуска (запрет уже на месте — скачивать не будет)
					}
				}
			}
		}
		os.Remove(filepath.Join(old, "VPNAuto.exe"))
		os.Remove(filepath.Join(old, "icon.ico"))
		if olds, _ := filepath.Glob(filepath.Join(old, "icon*.ico")); len(olds) > 0 {
			for _, o := range olds {
				os.Remove(o)
			}
		}
		os.Remove(old)
	}

	// прежние ярлыки «VPN Auto» убираем — программа теперь называется NETtool
	deskPS := `$d=[Environment]::GetFolderPath('Desktop'); foreach($n in 'NETtool.lnk','VPN Auto.lnk'){Remove-Item -LiteralPath (Join-Path $d $n) -ErrorAction SilentlyContinue};` +
		`Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Programs')) 'VPN Auto.lnk') -ErrorAction SilentlyContinue;`
	if wantDesk {
		deskPS = `$d=[Environment]::GetFolderPath('Desktop'); Remove-Item -LiteralPath (Join-Path $d 'VPN Auto.lnk') -ErrorAction SilentlyContinue; mk (Join-Path $d 'NETtool.lnk');` +
			`Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Programs')) 'VPN Auto.lnk') -ErrorAction SilentlyContinue;`
	}
	ps := fmt.Sprintf(`$w=New-Object -ComObject WScript.Shell;`+
		`function mk($p){$s=$w.CreateShortcut($p);$s.TargetPath=%s;$s.WorkingDirectory=%s;$s.IconLocation=%s;`+
		`$s.Description='NETtool by undr — автовыбор VPN-сервера, запрет и WARP';$s.Save()};`+
		`mk (Join-Path ([Environment]::GetFolderPath('Programs')) 'NETtool.lnk');`+deskPS+
		// закреплённые ярлыки (панель задач, «Пуск»), созданные пользователем, — тоже на значок из exe
		`$pin=Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned';`+
		`Get-ChildItem -LiteralPath $pin -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {`+
		`$s=$w.CreateShortcut($_.FullName); if($s.TargetPath -ieq `+psq(exe)+`){$s.IconLocation=`+psq(ico+",0")+`;$s.Save()}};`,
		psq(exe), psq(dir), psq(ico+",0"))
	runPS(ps)

	for _, kv := range [][3]string{
		{"DisplayName", "REG_SZ", "NETtool"},
		{"DisplayVersion", "REG_SZ", version},
		{"Publisher", "REG_SZ", "undr"},
		{"DisplayIcon", "REG_SZ", ico},
		{"InstallLocation", "REG_SZ", dir},
		{"UninstallString", "REG_SZ", `"` + exe + `" --uninstall`},
		{"NoModify", "REG_DWORD", "1"},
		{"NoRepair", "REG_DWORD", "1"},
	} {
		hidden("reg", "add", uninstKey, "/v", kv[0], "/t", kv[1], "/d", kv[2], "/f").Run()
	}

	hidden("ie4uinit.exe", "-show").Run() // обновить кэш значков (ярлыки, панель задач)

	if wantDef {
		// исключения Защитника — в том же запуске с правами администратора, что и запрет;
		// если запрет не выбран — отдельным запросом
		dd := filepath.Join(os.Getenv("LOCALAPPDATA"), "VPNAuto")
		os.MkdirAll(dd, 0755)
		if wantZap {
			os.WriteFile(filepath.Join(dd, "pending-defender"), []byte("1"), 0644)
		} else {
			runPS(fmt.Sprintf(`Start-Process -FilePath %s -ArgumentList '--defender' -Verb RunAs -Wait`, psq(exe)))
		}
	}
	if wantZap {
		// распаковка запрета и задача для запуска без UAC — один запрос прав администратора
		// сам запрет программа скачает с GitHub автора (в установщик не вшиваем — антивирусы ругаются на WinDivert)
		ps := fmt.Sprintf(`Start-Process -FilePath %s -ArgumentList '--zapret-setup' -Verb RunAs -Wait`, psq(exe))
		if _, err := runPS(ps); err != nil || !fileExists(filepath.Join(dir, "zapret", "bin", "winws.exe")) {
			msgBox("Запрет не установлен: не было разрешения администратора.\nЕго можно будет установить позже прямо из программы (режим «Запрет»).", 0x30)
		}
	}

	if wantWarp && !warpInstalled && fileExists(filepath.Join(dir, "zapret", "bin", "winws.exe")) {
		// WARP скачает и поставит сама программа (через задачу запрета, без лишних запросов UAC)
		dd := filepath.Join(os.Getenv("LOCALAPPDATA"), "VPNAuto")
		os.MkdirAll(dd, 0755)
		os.WriteFile(filepath.Join(dd, "pending-warp-install"), []byte("1"), 0644)
	}

	if wantTg {
		// TG WS Proxy программа скачает при старте, включит и будет обновлять
		dd := filepath.Join(os.Getenv("LOCALAPPDATA"), "VPNAuto")
		os.MkdirAll(dd, 0755)
		os.WriteFile(filepath.Join(dd, "pending-tgws-install"), []byte("1"), 0644)
	}

	if !silent { // при обновлении автозапуск не трогаем
		dd := filepath.Join(os.Getenv("LOCALAPPDATA"), "VPNAuto")
		os.MkdirAll(dd, 0755)
		v := "0"
		if wantAuto {
			v = "1"
		}
		os.WriteFile(filepath.Join(dd, "pending-autostart"), []byte(v), 0644)
	}

	if wantRun {
		c := exec.Command(exe)
		if updating {
			c = exec.Command(exe, "--updated") // новая копия подождёт, пока старая освободит порт
		}
		c.Dir = dir
		c.Start()
	} else {
		word := "установлен"
		if updating {
			word = "обновлён"
		}
		msgBox("Готово! NETtool "+word+".", 0x40)
	}
}

func fail(dir string, err error) {
	msgBox("Не удалось установить в папку:\n"+dir+"\n\n"+err.Error()+
		"\n\nВыберите другую папку (например, в своей папке пользователя) или запустите установщик от имени администратора.", 0x10)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
