package main

// Процесс режима шлюза (запускается задачей с правами администратора):
// перехват пересылаемых пакетов приставки через WinDivert (драйвер из комплекта запрета).

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const gatewaySupported = true

type wdAddr struct {
	Timestamp int64
	Bits      uint32 // Layer:8 Event:8 Sniffed Outbound Loopback Impostor IPv6 IPChecksum TCPChecksum UDPChecksum
	Reserved2 uint32
	IfIdx     uint32
	SubIfIdx  uint32
	Rest      [56]byte
}

const (
	wdLayerNetwork = 0
	wdLayerForward = 1
	wdOutbound     = 1 << 17
	wdSumsValid    = 1<<21 | 1<<22 | 1<<23
)

type winDivert struct {
	open, recv, send, close *syscall.LazyProc
}

func loadWinDivert() (*winDivert, error) {
	p := filepath.Join(zapretDir(), "bin", "WinDivert.dll")
	if _, err := os.Stat(p); err != nil {
		return nil, errors.New("нет драйвера WinDivert — установите запрет (режим «Запрет»)")
	}
	d := syscall.NewLazyDLL(p)
	if err := d.Load(); err != nil {
		return nil, err
	}
	return &winDivert{d.NewProc("WinDivertOpen"), d.NewProc("WinDivertRecv"), d.NewProc("WinDivertSend"), d.NewProc("WinDivertClose")}, nil
}

func (w *winDivert) Open(filter string, layer int, prio int16) (uintptr, error) {
	f, _ := syscall.BytePtrFromString(filter)
	h, _, err := w.open.Call(uintptr(unsafe.Pointer(f)), uintptr(layer), uintptr(prio), 0)
	if h == ^uintptr(0) {
		return 0, err
	}
	return h, nil
}

func (w *winDivert) Recv(h uintptr, buf []byte, a *wdAddr) (int, error) {
	var n uint32
	r, _, err := w.recv.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(a)))
	if r == 0 {
		return 0, err
	}
	return int(n), nil
}

func (w *winDivert) Send(h uintptr, b []byte, a *wdAddr) error {
	var n uint32
	r, _, err := w.send.Call(h, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(a)))
	if r == 0 {
		return err
	}
	return nil
}

type wdIO struct {
	w     *winDivert
	h     uintptr
	ifIdx uint32
}

func (x *wdIO) Inject(b []byte, outbound bool) error {
	a := wdAddr{Bits: wdLayerNetwork | wdSumsValid, IfIdx: x.ifIdx}
	if outbound {
		a.Bits |= wdOutbound
	}
	return x.w.Send(x.h, b, &a)
}

func gatewayMain() {
	fail := func(e string) {
		gwLog("%s", e)
		writeGWState(gwState{PID: os.Getpid(), Err: e, TS: time.Now().Unix()})
		os.Exit(1)
	}
	// второй экземпляр не нужен: если шлюз уже работает — тихо выходим, не трогая его состояние
	if s := readGWState(); s.PID > 0 && s.PID != os.Getpid() && s.Err == "" && time.Since(time.Unix(s.TS, 0)) < 6*time.Second {
		os.Exit(0)
	}
	c, err := readGWConfig()
	if err != nil || !c.On {
		os.Exit(0)
	}
	pc, err := netip.ParseAddr(c.PC)
	if err != nil || !pc.Is4() {
		fail("неверный адрес компьютера: " + c.PC)
	}
	w, err := loadWinDivert()
	if err != nil {
		fail(err.Error())
	}
	// подсеть компьютера — пакеты только от устройств этой сети
	netFilter := ""
	if ifs, err := net.Interfaces(); err == nil {
		for _, in := range ifs {
			addrs, _ := in.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(net.IP(pc.AsSlice())) {
					if c.IfIdx == 0 {
						c.IfIdx = in.Index
					}
					first := ipn.IP.Mask(ipn.Mask).To4()
					last := make(net.IP, 4)
					for i := range first {
						last[i] = first[i] | ^ipn.Mask[i]
					}
					netFilter = " and ip.SrcAddr >= " + first.String() + " and ip.SrcAddr <= " + last.String()
				}
			}
		}
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(pc.String(), strconv.Itoa(gwTCPPort)))
	if err != nil {
		fail("порт шлюза занят: " + err.Error())
	}
	hInj, err := w.Open("false", wdLayerNetwork, 0)
	if err != nil {
		fail("WinDivert не открылся (нужны права администратора): " + err.Error())
	}
	io := &wdIO{w: w, h: hInj, ifIdx: uint32(c.IfIdx)}
	g := newGateway(pc, io)
	g.cfg.Store(c)
	fwdFilter := "ip and !impostor and (tcp or udp) and ip.SrcAddr != " + pc.String() + netFilter
	hFwd, err := w.Open(fwdFilter, wdLayerForward, 10)
	if err != nil {
		fail("перехват пересылки не включился: " + err.Error())
	}
	hOut, err := w.Open("outbound and !loopback and ip and tcp and ip.SrcAddr == "+pc.String()+" and tcp.SrcPort == "+strconv.Itoa(gwTCPPort), wdLayerNetwork, 10)
	if err != nil {
		fail("перехват ответов не включился: " + err.Error())
	}
	gwLog("запущен: компьютер %s, интерфейс %d, режим %s", pc, c.IfIdx, c.Mode)

	go g.serveTCP(ln)
	go g.janitor()
	go func() { // пакеты приставки в интернет
		buf := make([]byte, 65535)
		for {
			var a wdAddr
			n, err := w.Recv(hFwd, buf, &a)
			if err != nil {
				gwLog("приём: %v", err)
				time.Sleep(50 * time.Millisecond)
				continue
			}
			if !g.onForward(buf[:n]) {
				w.Send(hFwd, buf[:n], &a)
			}
		}
	}()
	go func() { // ответы нашего приёмника приставке
		buf := make([]byte, 65535)
		for {
			var a wdAddr
			n, err := w.Recv(hOut, buf, &a)
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			if g.onOutbound(buf[:n]) {
				a.Bits |= wdSumsValid
			}
			w.Send(hOut, buf[:n], &a)
		}
	}()
	// следим за настройками: программа обновляет их каждые пару секунд
	for {
		time.Sleep(time.Second)
		nc, err := readGWConfig()
		// программа обновляет файл каждые 2 секунды; молчит 12 секунд — значит, закрыта
		if err != nil || !nc.On || time.Since(time.Unix(nc.TS, 0)) > 12*time.Second {
			gwLog("остановлен")
			w.close.Call(hFwd)
			w.close.Call(hOut)
			w.close.Call(hInj)
			writeGWState(gwState{PID: 0, TS: time.Now().Unix()})
			os.Exit(0)
		}
		if nc.IfIdx == 0 {
			nc.IfIdx = c.IfIdx
		}
		g.cfg.Store(nc)
		writeGWState(g.state(""))
	}
}

// Включить пересылку на сетевом адаптере и запустить процесс шлюза (выполняется в задаче администратора).
func gatewayStartElevated(ifIdx int) error {
	if ifIdx > 0 {
		hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Set-NetIPInterface -InterfaceIndex "+strconv.Itoa(ifIdx)+" -AddressFamily IPv4 -Forwarding Enabled").Run()
	}
	if s := readGWState(); s.PID > 0 && time.Since(time.Unix(s.TS, 0)) < 10*time.Second {
		return nil // уже работает
	}
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "--gateway")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x01000000} // без окна, вне job-объекта задачи
	if err := cmd.Start(); err != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		return cmd.Start()
	}
	return nil
}

func gatewayStopElevated(ifIdx int) {
	if ifIdx > 0 {
		hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Set-NetIPInterface -InterfaceIndex "+strconv.Itoa(ifIdx)+" -AddressFamily IPv4 -Forwarding Disabled").Run()
	}
}
