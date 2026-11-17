//go:build windows

package main

// Значок в трее (область уведомлений у часов) на чистом Win32 API.

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	shell32                = syscall.NewLazyDLL("shell32.dll")
	pGetModuleHandle       = kernel32.NewProc("GetModuleHandleW")
	pShellNotifyIcon       = shell32.NewProc("Shell_NotifyIconW")
	pRegisterClassEx       = user32.NewProc("RegisterClassExW")
	pCreateWindowEx        = user32.NewProc("CreateWindowExW")
	pDefWindowProc         = user32.NewProc("DefWindowProcW")
	pGetMessage            = user32.NewProc("GetMessageW")
	pTranslateMessage      = user32.NewProc("TranslateMessage")
	pDispatchMessage       = user32.NewProc("DispatchMessageW")
	pLoadImage             = user32.NewProc("LoadImageW")
	pGetSystemMetrics      = user32.NewProc("GetSystemMetrics")
	pCreatePopupMenu       = user32.NewProc("CreatePopupMenu")
	pAppendMenu            = user32.NewProc("AppendMenuW")
	pSetMenuDefaultItem    = user32.NewProc("SetMenuDefaultItem")
	pTrackPopupMenu        = user32.NewProc("TrackPopupMenu")
	pDestroyMenu           = user32.NewProc("DestroyMenu")
	pGetCursorPos          = user32.NewProc("GetCursorPos")
	pSetForegroundWindow   = user32.NewProc("SetForegroundWindow")
	pPostMessage           = user32.NewProc("PostMessageW")
	pRegisterWindowMessage = user32.NewProc("RegisterWindowMessageW")
	pFindWindow            = user32.NewProc("FindWindowW")
	pShowWindow            = user32.NewProc("ShowWindow")
)

const wmTray = 0x8001 // WM_APP + 1

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type winMsg struct {
	Hwnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       [2]int32
	LPrivate uint32
}

type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     uintptr
}

var tray struct {
	mu      sync.Mutex
	ok      bool
	hwnd    uintptr
	iconOn  uintptr
	iconOff uintptr
	on      bool
	tip     string
}

var taskbarCreated uintptr

func utf16p(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

func startTray() bool {
	ready := make(chan bool)
	go func() {
		runtime.LockOSThread()
		hInst, _, _ := pGetModuleHandle.Call(0)
		cls := utf16p("VPNAutoTray")
		wc := wndClassEx{LpfnWndProc: syscall.NewCallback(trayProc), HInstance: hInst, LpszClassName: cls}
		wc.CbSize = uint32(unsafe.Sizeof(wc))
		if r, _, _ := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			ready <- false
			return
		}
		hwnd, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(utf16p("VPNAutoTray"))),
			0, 0, 0, 0, 0, 0, 0, hInst, 0)
		if hwnd == 0 {
			ready <- false
			return
		}
		cx, _, _ := pGetSystemMetrics.Call(49) // SM_CXSMICON
		cy, _, _ := pGetSystemMetrics.Call(50)
		on, _, _ := pLoadImage.Call(hInst, 1, 1, cx, cy, 0)
		off, _, _ := pLoadImage.Call(hInst, 2, 1, cx, cy, 0)
		if off == 0 {
			off = on
		}
		taskbarCreated, _, _ = pRegisterWindowMessage.Call(uintptr(unsafe.Pointer(utf16p("TaskbarCreated"))))
		tray.mu.Lock()
		tray.hwnd, tray.iconOn, tray.iconOff, tray.tip = hwnd, on, off, "VPN Auto"
		tray.mu.Unlock()
		ok := trayNotify(0) // NIM_ADD
		tray.mu.Lock()
		tray.ok = ok
		tray.mu.Unlock()
		ready <- ok
		var m winMsg
		for {
			r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(r) <= 0 {
				return
			}
			pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
	return <-ready
}

func trayNotify(op uintptr) bool {
	tray.mu.Lock()
	var d notifyIconData
	d.CbSize = uint32(unsafe.Sizeof(d))
	d.HWnd = tray.hwnd
	d.UID = 1
	d.UFlags = 1 | 2 | 4 // MESSAGE | ICON | TIP
	d.UCallbackMessage = wmTray
	d.HIcon = tray.iconOff
	if tray.on {
		d.HIcon = tray.iconOn
	}
	tip := syscall.StringToUTF16(tray.tip)
	if len(tip) > 127 {
		tip = tip[:127]
	}
	copy(d.SzTip[:], tip)
	tray.mu.Unlock()
	r, _, _ := pShellNotifyIcon.Call(op, uintptr(unsafe.Pointer(&d)))
	return r != 0
}

func traySet(on bool, tip string) {
	tray.mu.Lock()
	changed := tray.ok && (tray.on != on || tray.tip != tip)
	tray.on, tray.tip = on, tip
	tray.mu.Unlock()
	if changed {
		trayNotify(1) // NIM_MODIFY
	}
}

func trayRemove() {
	tray.mu.Lock()
	ok := tray.ok
	tray.mu.Unlock()
	if ok {
		trayNotify(2) // NIM_DELETE
	}
}

func trayProc(hwnd, msg, wp, lp uintptr) uintptr {
	if hotkeyProc(hwnd, msg, wp) {
		return 0
	}
	if msg == wmTray {
		switch lp & 0xffff {
		case 0x202: // левый клик — мини-окно
			go openMini()
		case 0x203: // двойной клик — полное окно
			go openOrFocusUI()
		case 0x205: // правый клик
			showTrayMenu(hwnd)
		}
		return 0
	}
	if taskbarCreated != 0 && msg == taskbarCreated { // проводник перезапустился
		trayNotify(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, msg, wp, lp)
	return r
}

func trayCmd(q string) {
	go http.Get("http://" + uiAddr + "/api/tray?" + q)
}

const (
	mfString   = 0x0
	mfGrayed   = 0x1
	mfChecked  = 0x8
	mfPopup    = 0x10
	mfSep      = 0x800
	mfRadio    = 0x200
	idServer   = 1000
	idStrategy = 2000
)

func showTrayMenu(hwnd uintptr) {
	st := app.trayState()
	m, _, _ := pCreatePopupMenu.Call()
	add := func(menu, id, flags uintptr, text string) {
		pAppendMenu.Call(menu, flags, id, uintptr(unsafe.Pointer(utf16p(text))))
	}
	sep := func(menu uintptr) { pAppendMenu.Call(menu, mfSep, 0, 0) }
	flag := func(cond bool, f uintptr) uintptr {
		if cond {
			return f
		}
		return 0
	}

	add(m, 1, 0, "Открыть VPN Auto")
	sep(m)

	zapret := st.Mode == "zapret"
	name := "VPN"
	if zapret {
		name = "запрет"
	}
	switch {
	case st.On:
		add(m, 2, 0, "Выключить ("+name+")")
	case st.Ready:
		add(m, 2, 0, "Включить "+name)
	default:
		add(m, 2, mfGrayed, "Включить "+name+" (не готово)")
	}

	if st.ZSupported {
		add(m, 10, mfRadio|flag(!zapret, mfChecked), "Режим: VPN")
		add(m, 11, mfRadio|flag(zapret, mfChecked), "Режим: Запрет")
	}
	sep(m)

	// серверы VPN
	sub, _, _ := pCreatePopupMenu.Call()
	add(sub, idServer, flag(st.Pinned == "", mfChecked), "⚡ Авто — самый стабильный")
	if len(st.Servers) > 0 {
		sep(sub)
	}
	for i, s := range st.Servers {
		label := s.Name
		switch {
		case s.Ping > 0:
			label += fmt.Sprintf("    %d мс", s.Ping)
		case s.Ping < 0:
			label += "    нет связи"
		}
		f := flag(st.Pinned == s.Name, mfChecked)
		if i == st.Cur && st.Pinned == "" {
			label = "● " + label
		}
		add(sub, uintptr(idServer+1+i), f, label)
	}
	sep(sub)
	add(sub, 20, 0, "Обновить подписку")
	add(sub, 21, flag(st.DirectRu, mfChecked), "Российские сайты без VPN")
	add(m, sub, mfPopup, "Серверы VPN")

	if st.ZSupported {
		zs, _, _ := pCreatePopupMenu.Call()
		for i, f := range st.Strategies {
			add(zs, uintptr(idStrategy+i), flag(f == st.ZStrategy, mfChecked)|flag(st.ZBusy, mfGrayed), strategyTitle(f))
		}
		if len(st.Strategies) > 0 {
			sep(zs)
		}
		add(zs, 30, flag(st.ZBusy, mfGrayed), "Подобрать лучшую стратегию")
		add(zs, 31, 0, "Проверить обновления запрета")
		add(m, zs, mfPopup, "Стратегия запрета")

		warpText := "WARP через запрет"
		if !st.WarpInst {
			warpText += " (установить)"
		} else if st.WarpOn {
			warpText += " — подключён"
		}
		add(m, 12, flag(st.WarpWant, mfChecked), warpText)
	}
	if st.TgSupported {
		add(m, 14, flag(st.TgOn, mfChecked), "TG WS Proxy (ускорение Telegram)")
	}
	if st.HsSupported {
		add(m, 13, flag(st.HsOn, mfChecked), "Раздать доступ (точка доступа / локальная сеть)")
	}
	sep(m)
	add(m, 3, 0, "Выход")
	pSetMenuDefaultItem.Call(m, 1, 0)

	var pt [2]int32
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(hwnd)
	cmd, _, _ := pTrackPopupMenu.Call(m, 0x100|0x2, uintptr(pt[0]), uintptr(pt[1]), 0, hwnd, 0)
	pPostMessage.Call(hwnd, 0, 0, 0)
	pDestroyMenu.Call(m) // подменю удаляются вместе с главным

	on01 := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	switch {
	case cmd == 1:
		go openOrFocusUI()
	case cmd == 2:
		go func() {
			if st.On {
				app.allOff()
			} else if err := app.modeOn(); err != nil {
				msgBox(err.Error(), 0x30)
			}
		}()
	case cmd == 3:
		go shutdown()
	case cmd == 10:
		trayCmd("do=mode&mode=vpn")
	case cmd == 11:
		trayCmd("do=mode&mode=zapret")
	case cmd == 12:
		trayCmd("do=warp&on=" + on01(!st.WarpWant))
	case cmd == 13:
		trayCmd("do=hotspot&on=" + on01(!st.HsOn))
	case cmd == 14:
		trayCmd("do=tgws&on=" + on01(!st.TgOn))
	case cmd == 20:
		trayCmd("do=refresh")
	case cmd == 21:
		trayCmd("do=directru&on=" + on01(!st.DirectRu))
	case cmd == 30:
		trayCmd("do=test")
	case cmd == 31:
		trayCmd("do=zupdate")
	case cmd == idServer:
		trayCmd("do=select&name=")
	case cmd > idServer && cmd <= idServer+uintptr(len(st.Servers)):
		trayCmd("do=select&name=" + url.QueryEscape(st.Servers[cmd-idServer-1].Name))
	case cmd >= idStrategy && cmd < idStrategy+uintptr(len(st.Strategies)):
		trayCmd("do=strategy&file=" + url.QueryEscape(st.Strategies[cmd-idStrategy]))
	}
}

// Если окно уже открыто — выводим его вперёд, иначе открываем.
func openOrFocusUI() {
	h := findUIWindow()
	if h != 0 {
		pShowWindow.Call(h, 9) // SW_RESTORE
		pSetForegroundWindow.Call(h)
		return
	}
	openUI()
}

// ---------- окно интерфейса как отдельное приложение на панели задач ----------
// Окно открывается через Edge, и Windows считает его окном Edge (значок Edge при закреплении).
// Назначаем окну свой AppUserModelID, команду перезапуска и значок — тогда закреплённый
// значок будет с ключиком и будет запускать VPN Auto.

var (
	ole32                        = syscall.NewLazyDLL("ole32.dll")
	pCoInitializeEx              = ole32.NewProc("CoInitializeEx")
	pSHGetPropertyStoreForWindow = shell32.NewProc("SHGetPropertyStoreForWindow")
)

type winGUID struct {
	D1 uint32
	D2 uint16
	D3 uint16
	D4 [8]byte
}

type propKey struct {
	Fmt winGUID
	Pid uint32
}

type propVariant struct {
	Vt  uint16
	R1  uint16
	R2  uint16
	R3  uint16
	Ptr uintptr
	Pad uintptr
}

var (
	iidPropertyStore = winGUID{0x886D8EEB, 0x8CF2, 0x4446, [8]byte{0x8D, 0x02, 0xCD, 0xBA, 0x1D, 0xBD, 0xCF, 0x99}}
	fmtAppUserModel  = winGUID{0x9F4C2855, 0x9F79, 0x4B39, [8]byte{0xA8, 0xD0, 0xE1, 0xD4, 0x2D, 0xE1, 0xD5, 0xF3}}
)

const appUserModelID = "VPNAuto.App"

func findUIWindow() uintptr { return findWindowTitle("VPN Auto") }

func brandWindow(hwnd uintptr) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pCoInitializeEx.Call(0, 2)
	var storeP unsafe.Pointer
	if r, _, _ := pSHGetPropertyStoreForWindow.Call(hwnd, uintptr(unsafe.Pointer(&iidPropertyStore)), uintptr(unsafe.Pointer(&storeP))); r != 0 || storeP == nil {
		return false
	}
	store := uintptr(storeP)
	vtbl := *(*[8]uintptr)(*(*unsafe.Pointer)(storeP))
	exe, _ := os.Executable()
	values := []struct {
		pid uint32
		val string
	}{
		{5, appUserModelID},    // System.AppUserModel.ID
		{2, `"` + exe + `"`},   // RelaunchCommand
		{3, relaunchIcon(exe)}, // RelaunchIconResource
		{4, "VPN Auto"},        // RelaunchDisplayNameResource
	}
	ok := true
	// команду перезапуска и значок задаём раньше ID — так требует Windows
	for _, i := range []int{1, 2, 3, 0} {
		v := values[i]
		s := utf16p(v.val)
		key := propKey{fmtAppUserModel, v.pid}
		pv := propVariant{Vt: 31, Ptr: uintptr(unsafe.Pointer(s))} // VT_LPWSTR
		r, _, _ := syscall.SyscallN(vtbl[6], store, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pv)))
		runtime.KeepAlive(s)
		if r != 0 {
			ok = false
		}
	}
	syscall.SyscallN(vtbl[7], store) // Commit
	syscall.SyscallN(vtbl[2], store) // Release
	return ok
}

// Ждём появления окна и помечаем его.
func afterOpenUI() {
	go func() {
		for i := 0; i < 60; i++ {
			if h := findUIWindow(); h != 0 {
				frameLoop()
				if !brandWindow(h) {
					log.Println("не удалось задать AppUserModelID окну")
				}
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
}

// ---------- уведомления, горячая клавиша, мини-окно ----------
const hotkeySupported = true
const wmHotkeyCtl = 0x8002 // WM_APP + 2
const wmHotkey = 0x0312

var (
	pRegisterHotKey   = user32.NewProc("RegisterHotKey")
	pUnregisterHotKey = user32.NewProc("UnregisterHotKey")
)

// Уведомление Windows от имени значка в трее.
func notify(title, text string) {
	tray.mu.Lock()
	ok, hwnd := tray.ok, tray.hwnd
	tray.mu.Unlock()
	if !ok {
		return
	}
	var d notifyIconData
	d.CbSize = uint32(unsafe.Sizeof(d))
	d.HWnd = hwnd
	d.UID = 1
	d.UFlags = 0x10 // NIF_INFO
	t := syscall.StringToUTF16(text)
	if len(t) > 255 {
		t = t[:255]
	}
	copy(d.SzInfo[:], t)
	tt := syscall.StringToUTF16(title)
	if len(tt) > 63 {
		tt = tt[:63]
	}
	copy(d.SzInfoTitle[:], tt)
	d.DwInfoFlags = 0x1 // NIIF_INFO
	pShellNotifyIcon.Call(1, uintptr(unsafe.Pointer(&d)))
}

// Ctrl+Alt+V — включить/выключить. Регистрировать нужно в потоке окна трея.
func hotkeySet(on bool) {
	tray.mu.Lock()
	hwnd := tray.hwnd
	tray.mu.Unlock()
	if hwnd == 0 {
		return
	}
	var w uintptr
	if on {
		w = 1
	}
	pPostMessage.Call(hwnd, wmHotkeyCtl, w, 0)
}

func hotkeyProc(hwnd, msg, wp uintptr) bool {
	switch msg {
	case wmHotkeyCtl:
		pUnregisterHotKey.Call(hwnd, 1)
		if wp == 1 {
			// MOD_ALT|MOD_CONTROL|MOD_NOREPEAT, 'V'
			if r, _, _ := pRegisterHotKey.Call(hwnd, 1, 0x1|0x2|0x4000, 0x56); r == 0 {
				log.Println("Ctrl+Alt+V уже занята другой программой")
			}
		}
		return true
	case wmHotkey:
		go func() {
			if app.anyOn() {
				app.allOff()
				notify("VPN Auto", "Выключено (Ctrl+Alt+V)")
			} else if err := app.modeOn(); err != nil {
				notify("VPN Auto", err.Error())
			} else {
				notify("VPN Auto", "Включено (Ctrl+Alt+V)")
			}
		}()
		return true
	}
	return false
}

// Мини-окно у трея.
func openMini() {
	if h := findWindowTitle("VPN Auto · мини"); h != 0 {
		pShowWindow.Call(h, 9)
		pSetForegroundWindow.Call(h)
		return
	}
	openUIURL("http://"+uiAddr+"/?mini=1", "340,500")
}

// Закрыть окна интерфейса (полное и мини) и процессы браузера с профилем программы.
func closeUIWindows() {
	for _, t := range []string{"VPN Auto", "VPN Auto · мини"} {
		for i := 0; i < 10; i++ {
			h := findWindowTitle(t)
			if h == 0 {
				break
			}
			pPostMessage.Call(h, 0x0010, 0, 0) // WM_CLOSE
			time.Sleep(150 * time.Millisecond)
		}
	}
	prof := strings.ReplaceAll(filepath.Join(dataDir, "ui"), "'", "''")
	ps := `Get-CimInstance Win32_Process -Filter "Name='msedge.exe' or Name='chrome.exe'" | ` +
		`Where-Object { $_.CommandLine -like '*` + prof + `*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`
	hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
}

func relaunchIcon(exe string) string {
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), "icon-*.ico")); len(m) > 0 {
		return m[len(m)-1] + ",0"
	}
	return exe + ",0"
}
