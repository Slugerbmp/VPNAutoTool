package main

// Окно интерфейса — обычное окно Edge/Chrome в режиме приложения.
// (Встраивание окна Edge в своё окно-рамку давало зависания ввода между процессами,
// поэтому от него отказались: надёжность важнее.) Рамке задаём только тёмный/светлый
// режим через DWM — это безопасно и ничего не ломает.

import (
	"net/http"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	dwmapi              = syscall.NewLazyDLL("dwmapi.dll")
	pDwmSetWindowAttrib = dwmapi.NewProc("DwmSetWindowAttribute")
	pSetWindowRgn       = user32.NewProc("SetWindowRgn")
	pGetWindowLongPtr   = user32.NewProc("GetWindowLongPtrW")
	pSetWindowLongPtr   = user32.NewProc("SetWindowLongPtrW")
	pSetParent          = user32.NewProc("SetParent")
	pGetParent          = user32.NewProc("GetParent")
	pSetWindowPos       = user32.NewProc("SetWindowPos")
)

var uiTitles = []string{"VPN Auto", "VPN Auto · мини"}

var frame = struct {
	sync.Mutex
	dark bool
	loop bool
}{dark: true}

func findWindowTitle(t string) uintptr {
	h, _, _ := pFindWindow.Call(uintptr(unsafe.Pointer(utf16p("Chrome_WidgetWin_1"))), uintptr(unsafe.Pointer(utf16p(t))))
	return h
}

// Тёмный режим системных частей окна по теме программы.
func setDwm(h uintptr) {
	frame.Lock()
	dark := frame.dark
	frame.Unlock()
	d := uint32(0)
	if dark {
		d = 1
	}
	pDwmSetWindowAttrib.Call(h, 20, uintptr(unsafe.Pointer(&d)), 4) // DWMWA_USE_IMMERSIVE_DARK_MODE
}

// Восстановить окно, если его испортила прошлая версия (регион/стили/встраивание).
func repairWindow(h uintptr) {
	pSetWindowRgn.Call(h, 0, 1)
	if p, _, _ := pGetParent.Call(h); p != 0 {
		pSetParent.Call(h, 0)
	}
	st, _, _ := pGetWindowLongPtr.Call(h, ^uintptr(15)) // GWL_STYLE
	const need = 0x00C00000 | 0x00040000                // WS_CAPTION | WS_THICKFRAME
	if st != 0 && (st&need != need || st&0x40000000 != 0) {
		pSetWindowLongPtr.Call(h, ^uintptr(15), (st|need)&^0x40000000)
		pSetWindowPos.Call(h, 0, 0, 0, 0, 0, 0x0020|0x0002|0x0001|0x0004|0x0010)
	}
}

func frameLoop() {
	frame.Lock()
	if frame.loop {
		frame.Unlock()
		return
	}
	frame.loop = true
	frame.Unlock()
	go func() {
		defer func() { frame.Lock(); frame.loop = false; frame.Unlock() }()
		for i := 0; i < 20; i++ {
			for _, t := range uiTitles {
				if h := findWindowTitle(t); h != 0 {
					repairWindow(h)
					setDwm(h)
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
}

func frameRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/win", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has("dark") {
			frame.Lock()
			frame.dark = q.Get("dark") == "1"
			frame.Unlock()
			frameLoop()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"custom":false}`))
	})
}
