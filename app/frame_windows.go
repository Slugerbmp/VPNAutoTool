package main

// Рамка окна в цвет темы.
//
// Edge/Chrome рисует свой заголовок сам и возвращает его при любой попытке убрать.
// Поэтому окно Edge помещается ВНУТРЬ нашего окна без рамки и сдвигается так, чтобы
// его заголовок и края оказались за пределами нашего окна (дочернее окно Windows всегда
// обрезается родителем). Полосу заголовка (VPN AUTO — ×) рисует сама страница.
//
// Надёжность: окно-рамка живёт в отдельном потоке со своей очередью сообщений; из
// обработчиков HTTP в него только ОТПРАВЛЯЮТСЯ сообщения (PostMessage) — ничего не ждём,
// поэтому зависание окна Edge не может подвесить программу. Если встроить окно не удалось —
// остаётся обычное окно Edge с тёмной/светлой системной рамкой.

import (
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	dwmapi               = syscall.NewLazyDLL("dwmapi.dll")
	pDwmSetWindowAttrib  = dwmapi.NewProc("DwmSetWindowAttribute")
	gdi32                = syscall.NewLazyDLL("gdi32.dll")
	pCreateSolidBrush    = gdi32.NewProc("CreateSolidBrush")
	pDeleteObject        = gdi32.NewProc("DeleteObject")
	pGetWindowRect       = user32.NewProc("GetWindowRect")
	pGetClientRect       = user32.NewProc("GetClientRect")
	pSetWindowPos        = user32.NewProc("SetWindowPos")
	pFindWindowEx        = user32.NewProc("FindWindowExW")
	pIsWindow            = user32.NewProc("IsWindow")
	pIsIconic            = user32.NewProc("IsIconic")
	pGetClassName        = user32.NewProc("GetClassNameW")
	pSetParent           = user32.NewProc("SetParent")
	pGetWindowLongPtr    = user32.NewProc("GetWindowLongPtrW")
	pSetWindowLongPtr    = user32.NewProc("SetWindowLongPtrW")
	pSetWindowRgn        = user32.NewProc("SetWindowRgn")
	pDestroyWindow       = user32.NewProc("DestroyWindow")
	pSetTimer            = user32.NewProc("SetTimer")
	pFillRect            = user32.NewProc("FillRect")
	pInvalidateRect      = user32.NewProc("InvalidateRect")
	pSystemParametersInf = user32.NewProc("SystemParametersInfoW")
	pSetThreadDpiCtx     = user32.NewProc("SetThreadDpiAwarenessContext")
	pLoadCursor          = user32.NewProc("LoadCursorW")
)

type rect struct{ L, T, R, B int32 }

func winRect(h uintptr) (r rect) {
	pGetWindowRect.Call(h, uintptr(unsafe.Pointer(&r)))
	return
}

const (
	wmAdopt  = 0x8000 + 21
	wmStart  = 0x8000 + 22
	wmMove   = 0x8000 + 23
	wmSize   = 0x8000 + 24
	wmCorner = 0x8000 + 25
	wmTheme  = 0x8000 + 26
)

type frameHost struct {
	hwnd, edge uintptr
	title      string
	start      rect
}

var uiTitles = []string{"NETtool", "NETtool · мини"}

var frame = struct {
	sync.Mutex
	ctl     uintptr
	byTitle map[string]*frameHost
	byHwnd  map[uintptr]*frameHost
	dark    bool
	loop    bool
	brush   uintptr
	failed  map[uintptr]int
}{byTitle: map[string]*frameHost{}, byHwnd: map[uintptr]*frameHost{}, dark: true, failed: map[uintptr]int{}}

// Окно интерфейса по заголовку: наша рамка, иначе само окно Edge.
func findWindowTitle(t string) uintptr {
	frame.Lock()
	fh := frame.byTitle[t]
	frame.Unlock()
	if fh != nil {
		if r, _, _ := pIsWindow.Call(fh.hwnd); r != 0 {
			return fh.hwnd
		}
	}
	return findEdgeWindow(t)
}

func findEdgeWindow(t string) uintptr {
	h, _, _ := pFindWindow.Call(uintptr(unsafe.Pointer(utf16p("Chrome_WidgetWin_1"))), uintptr(unsafe.Pointer(utf16p(t))))
	return h
}

func className(h uintptr) string {
	buf := make([]uint16, 128)
	n, _, _ := pGetClassName.Call(h, uintptr(unsafe.Pointer(&buf[0])), 128)
	return syscall.UTF16ToString(buf[:n])
}

// Окно с содержимым страницы внутри окна Edge.
func renderWidget(h uintptr) uintptr {
	var found uintptr
	var walk func(parent uintptr, depth int)
	walk = func(parent uintptr, depth int) {
		var c uintptr
		for found == 0 {
			c, _, _ = pFindWindowEx.Call(parent, c, 0, 0)
			if c == 0 {
				return
			}
			if className(c) == "Chrome_RenderWidgetHostHWND" {
				r := winRect(c)
				if r.R-r.L >= 50 && r.B-r.T >= 50 {
					found = c
					return
				}
			}
			if depth < 3 {
				walk(c, depth+1)
			}
		}
	}
	walk(h, 0)
	return found
}

// ---------- поток окон-рамок ----------
func frameThreadStart() bool {
	frame.Lock()
	if frame.ctl != 0 {
		frame.Unlock()
		return true
	}
	frame.Unlock()
	ready := make(chan uintptr)
	go func() {
		runtime.LockOSThread()
		pSetThreadDpiCtx.Call(^uintptr(3)) // PER_MONITOR_AWARE_V2, как у Edge
		hInst, _, _ := pGetModuleHandle.Call(0)
		big, _, _ := pLoadImage.Call(hInst, 1, 1, 0, 0, 0x40)
		small, _, _ := pLoadImage.Call(hInst, 1, 1, 16, 16, 0)
		cur, _, _ := pLoadCursor.Call(0, 32512)
		cls := utf16p("VPNAutoFrame")
		wc := wndClassEx{Style: 0x00020000 | 0x0003, LpfnWndProc: syscall.NewCallback(frameProc), HInstance: hInst,
			LpszClassName: cls, HIcon: big, HIconSm: small, HCursor: cur}
		wc.CbSize = uint32(unsafe.Sizeof(wc))
		pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
		ctlCls := utf16p("VPNAutoFrameCtl")
		wc2 := wndClassEx{LpfnWndProc: syscall.NewCallback(frameCtlProc), HInstance: hInst, LpszClassName: ctlCls}
		wc2.CbSize = uint32(unsafe.Sizeof(wc2))
		pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc2)))
		ctl, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(ctlCls)), 0, 0, 0, 0, 0, 0, ^uintptr(2), 0, hInst, 0)
		frame.Lock()
		frame.ctl = ctl
		frame.Unlock()
		ready <- ctl
		if ctl == 0 {
			return
		}
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
	return <-ready != 0
}

func frameCtlProc(hwnd, msg, wp, lp uintptr) uintptr {
	if msg == wmAdopt {
		adopt(wp, uiTitles[lp])
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, msg, wp, lp)
	return r
}

// Принять окно Edge в нашу рамку (в потоке рамок).
func adopt(edge uintptr, title string) {
	frame.Lock()
	if fh := frame.byTitle[title]; fh != nil {
		if r, _, _ := pIsWindow.Call(fh.hwnd); r != 0 {
			frame.Unlock()
			return
		}
	}
	frame.Unlock()
	rw := renderWidget(edge)
	if rw == 0 {
		return // страница ещё не создана — попробуем позже
	}
	if r, _, _ := pIsIconic.Call(edge); r != 0 {
		pShowWindow.Call(edge, 9)
	}
	w, c := winRect(edge), winRect(rw)
	hInst, _, _ := pGetModuleHandle.Call(0)
	const style = 0x80000000 | 0x02000000 | 0x00080000 | 0x00020000 // POPUP|CLIPCHILDREN|SYSMENU|MINIMIZEBOX
	h, _, _ := pCreateWindowEx.Call(0x00040000, uintptr(unsafe.Pointer(utf16p("VPNAutoFrame"))), uintptr(unsafe.Pointer(utf16p(title))), style,
		uintptr(c.L), uintptr(c.T), uintptr(c.R-c.L), uintptr(c.B-c.T), 0, 0, hInst, 0)
	if h == 0 {
		frame.Lock()
		frame.failed[edge]++
		frame.Unlock()
		return
	}
	fh := &frameHost{hwnd: h, edge: edge, title: title}
	frame.Lock()
	frame.byTitle[title], frame.byHwnd[h] = fh, fh
	frame.Unlock()
	setDwm(h)
	brandWindow(h)
	pSetWindowRgn.Call(edge, 0, 0)
	st, _, _ := pGetWindowLongPtr.Call(edge, ^uintptr(15))
	if r, _, _ := pSetParent.Call(edge, h); r == 0 {
		pDestroyWindow.Call(h)
		frame.Lock()
		frame.failed[edge]++
		frame.Unlock()
		return
	}
	pSetWindowLongPtr.Call(edge, ^uintptr(15), (st|0x40000000)&^0x80000000) // +WS_CHILD −WS_POPUP
	pSetWindowPos.Call(edge, 0, uintptr(w.L-c.L), uintptr(w.T-c.T), uintptr(w.R-w.L), uintptr(w.B-w.T), 0x0004|0x0010|0x0020|0x0040)
	align(fh)
	pShowWindow.Call(h, 5)
	pSetForegroundWindow.Call(h)
	pSetTimer.Call(h, 1, 300, 0)
}

// Подогнать окно Edge так, чтобы содержимое страницы точно совпало с нашим окном.
// SWP_ASYNCWINDOWPOS — не ждём поток Edge.
func align(fh *frameHost) {
	if r, _, _ := pIsIconic.Call(fh.hwnd); r != 0 {
		return
	}
	rw := renderWidget(fh.edge)
	if rw == 0 {
		return
	}
	H, R, E := winRect(fh.hwnd), winRect(rw), winRect(fh.edge)
	dx, dy := R.L-H.L, R.T-H.T
	dw, dh := (H.R-H.L)-(R.R-R.L), (H.B-H.T)-(R.B-R.T)
	if dx == 0 && dy == 0 && dw == 0 && dh == 0 {
		return
	}
	pSetWindowPos.Call(fh.edge, 0, uintptr(E.L-H.L-dx), uintptr(E.T-H.T-dy), uintptr(E.R-E.L+dw), uintptr(E.B-E.T+dh), 0x0004|0x0010|0x4000)
}

func frameProc(hwnd, msg, wp, lp uintptr) uintptr {
	frame.Lock()
	fh := frame.byHwnd[hwnd]
	frame.Unlock()
	if fh != nil {
		switch msg {
		case 0x0113: // WM_TIMER
			if r, _, _ := pIsWindow.Call(fh.edge); r == 0 {
				pDestroyWindow.Call(hwnd)
				return 0
			}
			align(fh)
			return 0
		case 0x0005: // WM_SIZE
			align(fh)
		case 0x0014: // WM_ERASEBKGND
			var rc rect
			pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
			pFillRect.Call(wp, uintptr(unsafe.Pointer(&rc)), themeBrush())
			return 1
		case 0x0010: // WM_CLOSE — закрываем страницу; наше окно уйдёт следом
			pPostMessage.Call(fh.edge, 0x0010, 0, 0)
			return 0
		case 0x0002: // WM_DESTROY
			frame.Lock()
			delete(frame.byHwnd, hwnd)
			if frame.byTitle[fh.title] == fh {
				delete(frame.byTitle, fh.title)
			}
			frame.Unlock()
		case wmStart:
			fh.start = winRect(hwnd)
			return 0
		case wmMove:
			s := fh.start
			pSetWindowPos.Call(hwnd, 0, uintptr(s.L+int32(wp)), uintptr(s.T+int32(lp)), 0, 0, 0x0001|0x0004|0x0010)
			return 0
		case wmSize:
			s := fh.start
			w, h := max(s.R-s.L+int32(wp), 300), max(s.B-s.T+int32(lp), 300)
			pSetWindowPos.Call(hwnd, 0, 0, 0, uintptr(w), uintptr(h), 0x0002|0x0004|0x0010)
			return 0
		case wmCorner:
			var wa rect
			pSystemParametersInf.Call(0x0030, 0, uintptr(unsafe.Pointer(&wa)), 0)
			cur := winRect(hwnd)
			pSetWindowPos.Call(hwnd, 0, uintptr(wa.R-12-(cur.R-cur.L)), uintptr(wa.B-12-(cur.B-cur.T)), 0, 0, 0x0001|0x0004|0x0010)
			return 0
		case wmTheme:
			setDwm(hwnd)
			pInvalidateRect.Call(hwnd, 0, 1)
			return 0
		}
	}
	r, _, _ := pDefWindowProc.Call(hwnd, msg, wp, lp)
	return r
}

func themeBrush() uintptr {
	frame.Lock()
	defer frame.Unlock()
	if frame.brush == 0 {
		c := uintptr(0x00FAFAFA)
		if frame.dark {
			c = 0x000A0A0A
		}
		frame.brush, _, _ = pCreateSolidBrush.Call(c)
	}
	return frame.brush
}

// Тёмный/светлый режим системных частей, цвет заголовка (если окно не встроено), прямые углы.
func setDwm(h uintptr) {
	frame.Lock()
	dark := frame.dark
	frame.Unlock()
	var d, cap, txt uint32 = 0, 0x00FAFAFA, 0x000A0A0A
	if dark {
		d, cap, txt = 1, 0x000A0A0A, 0x00F2F2F2
	}
	for _, a := range []struct {
		id uintptr
		v  uint32
	}{{20, d}, {35, cap}, {36, txt}, {33, 1}, {34, 0xFFFFFFFE}} {
		v := a.v
		pDwmSetWindowAttrib.Call(h, a.id, uintptr(unsafe.Pointer(&v)), 4)
	}
}

// Следим за окнами Edge, пока они открыты: новые сразу принимаем в рамку.
func frameLoop() {
	frame.Lock()
	if frame.loop {
		frame.Unlock()
		return
	}
	frame.loop = true
	frame.Unlock()
	if !frameThreadStart() {
		frame.Lock()
		frame.loop = false
		frame.Unlock()
		return
	}
	go func() {
		defer func() { frame.Lock(); frame.loop = false; frame.Unlock() }()
		idle := 0
		for idle < 50 {
			seen := false
			for i, t := range uiTitles {
				if e := findEdgeWindow(t); e != 0 {
					seen = true
					frame.Lock()
					ctl, tries := frame.ctl, frame.failed[e]
					frame.Unlock()
					if tries < 5 {
						pPostMessage.Call(ctl, wmAdopt, e, uintptr(i))
					} else {
						setDwm(e) // встроить не удалось — хотя бы системная рамка в цвет темы
					}
				}
				frame.Lock()
				if frame.byTitle[t] != nil {
					seen = true
				}
				frame.Unlock()
			}
			if seen {
				idle = 0
			} else {
				idle++
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
}

func frameRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/win", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has("dark") {
			dark := q.Get("dark") == "1"
			frame.Lock()
			changed := frame.dark != dark
			frame.dark = dark
			if changed && frame.brush != 0 {
				pDeleteObject.Call(frame.brush)
				frame.brush = 0
			}
			hs := make([]uintptr, 0, len(frame.byHwnd))
			for h := range frame.byHwnd {
				hs = append(hs, h)
			}
			frame.Unlock()
			if changed {
				for _, h := range hs {
					pPostMessage.Call(h, wmTheme, 0, 0)
				}
			}
		}
		frameLoop()
		frame.Lock()
		fh := frame.byTitle[q.Get("t")]
		frame.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if fh == nil {
			if q.Get("do") == "close" {
				if e := findEdgeWindow(q.Get("t")); e != 0 {
					pPostMessage.Call(e, 0x0010, 0, 0)
				}
			}
			w.Write([]byte(`{"custom":false}`))
			return
		}
		atoi := func(k string) uintptr { n, _ := strconv.Atoi(q.Get(k)); return uintptr(int32(n)) }
		// только PostMessage: окно-рамка обработает в своём потоке, HTTP ничего не ждёт
		switch q.Get("do") {
		case "start":
			pPostMessage.Call(fh.hwnd, wmStart, 0, 0)
		case "move":
			pPostMessage.Call(fh.hwnd, wmMove, atoi("dx"), atoi("dy"))
		case "size":
			pPostMessage.Call(fh.hwnd, wmSize, atoi("dx"), atoi("dy"))
		case "corner":
			pPostMessage.Call(fh.hwnd, wmCorner, 0, 0)
		case "min":
			pShowWindow.Call(fh.hwnd, 6)
		case "close":
			pPostMessage.Call(fh.hwnd, 0x0010, 0, 0)
		}
		w.Write([]byte(`{"custom":true}`))
	})
}
