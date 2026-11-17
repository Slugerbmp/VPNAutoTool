package main

// Режимы работы: «vpn» (Xray + системный прокси) и «zapret» (winws, только Windows) + WARP.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type zInfo struct {
	mu sync.Mutex
	zData
}

type zData struct {
	running        bool
	busy           bool
	busyText       string
	err            string
	latest         string
	warpInst       bool
	warpOn         bool
	warpBusy       bool
	warpErr        string
	warpInstalling bool
	hsOn           bool
	hsBusy         bool
	hsErr          string
	hsInfo         hsState
	hsLAN          bool
	hsNote         string
	tgInstalled    bool
	tgRunning      bool
	tgBusy         bool
	tgErr          string
	tgVersion      string
}

var zi = &zInfo{}

func (a *App) mode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.settings.Mode == "zapret" && zapretSupported {
		return "zapret"
	}
	return "vpn"
}

func zSet(f func(z *zInfo)) { zi.mu.Lock(); f(zi); zi.mu.Unlock() }

// фоновое наблюдение: работает ли winws, подключён ли WARP
func (a *App) zapretMonitor() {
	if !zapretSupported {
		return
	}
	n := 0
	for {
		run := winwsRunning()
		zSet(func(z *zInfo) { z.running = run })
		if n%3 == 0 {
			inst := warpCLI() != ""
			on := inst && warpConnected()
			zSet(func(z *zInfo) { z.warpInst, z.warpOn = inst, on })
		}
		n++
		time.Sleep(3 * time.Second)
	}
}

// проверка новой версии запрета: при старте и каждые 6 часов
func (a *App) zapretUpdater() {
	if !zapretSupported {
		return
	}
	time.Sleep(20 * time.Second)
	for {
		a.zapretCheckUpdate(false)
		time.Sleep(6 * time.Hour)
	}
}

func (a *App) zapretCheckUpdate(manual bool) {
	latest, err := zapretLatestVersion()
	if err != nil {
		if manual {
			zSet(func(z *zInfo) { z.err = "не удалось проверить обновления: " + err.Error() })
		}
		return
	}
	zSet(func(z *zInfo) { z.latest = latest })
	local := zapretVersionOf(zapretDir())
	if !zapretInstalled() || !versionNewer(latest, local) || !zapretTaskExists() {
		return
	}
	a.mu.Lock()
	strategy, warp := a.settings.ZStrategy, a.settings.Warp
	a.mu.Unlock()
	zSet(func(z *zInfo) {
		z.busy, z.busyText, z.err = true, "Обновляю запрет до "+latest+"…", ""
	})
	_, err = zapretRun(zCmd{Action: "update", Strategy: strategy, Warp: warp}, 5*time.Minute)
	zSet(func(z *zInfo) {
		z.busy = false
		if err != nil {
			z.err = "обновление не удалось: " + err.Error()
		}
	})
	if err == nil {
		a.mu.Lock()
		a.event = fmt.Sprintf("%s — запрет обновлён до версии %s", time.Now().Format("15:04"), latest)
		if _, e := os.Stat(filepath.Join(zapretDir(), strategy)); e != nil {
			a.settings.ZStrategy = "" // стратегию переименовали — при включении подберём заново
			a.saveSettings()
		}
		a.mu.Unlock()
	}
}

func (a *App) zapretBusy() bool { zi.mu.Lock(); defer zi.mu.Unlock(); return zi.busy }

// Включить запрет (асинхронно).
func (a *App) zapretOn() error {
	if !zapretSupported {
		return errNoZapretMsg
	}
	if a.zapretBusy() {
		return fmt.Errorf("запрет занят, подождите")
	}
	a.powerOff() // VPN и запрет одновременно не включаем
	if !a.fallbackActive() && !a.consoleWantsCore() {
		stopCore() // в режиме запрета ядро VPN не работает (кроме входа Xbox для приставок)
	}
	go func() {
		zSet(func(z *zInfo) { z.busy, z.err = true, "" })
		defer zSet(func(z *zInfo) { z.busy = false })
		if !zapretInstalled() {
			zSet(func(z *zInfo) { z.busyText = "Скачиваю запрет…" })
			if _, err := zapretRun(zCmd{Action: "update"}, 5*time.Minute); err != nil {
				zSet(func(z *zInfo) { z.err = err.Error() })
				return
			}
		}
		a.mu.Lock()
		strategy, warp := a.settings.ZStrategy, a.settings.Warp
		a.mu.Unlock()
		if _, err := os.Stat(filepath.Join(zapretDir(), strategy)); strategy == "" || err != nil {
			a.zapretTestSync(warp)
		} else {
			zSet(func(z *zInfo) { z.busyText = "Запускаю запрет…" })
			if _, err := zapretRun(zCmd{Action: "start", Strategy: strategy, Warp: warp}, 25*time.Second); err != nil {
				zSet(func(z *zInfo) { z.err = err.Error() })
				return
			}
		}
		zSet(func(z *zInfo) { z.running = winwsRunning() })
		if warp && warpCLI() != "" {
			a.warpUp()
		}
	}()
	return nil
}

func (a *App) zapretTestSync(warp bool) {
	zSet(func(z *zInfo) { z.busyText = "Подбираю лучшую стратегию…" })
	st, err := zapretRun(zCmd{Action: "test", Warp: warp}, 15*time.Minute)
	if err != nil {
		zSet(func(z *zInfo) { z.err = err.Error() })
		return
	}
	a.mu.Lock()
	a.settings.ZStrategy = st.Best
	a.saveSettings()
	a.event = fmt.Sprintf("%s — лучшая стратегия запрета: %s", time.Now().Format("15:04"), strategyTitle(st.Best))
	a.mu.Unlock()
}

func (a *App) zapretOff() {
	if !zapretSupported {
		return
	}
	zi.mu.Lock()
	wOn, wBusy := zi.warpOn, zi.warpBusy
	zi.mu.Unlock()
	if wOn || wBusy {
		warpDisconnect() // в том числе прерывает идущую попытку подключения
	}
	if winwsRunning() {
		if _, err := zapretRun(zCmd{Action: "stop"}, 15*time.Second); err != nil {
			zSet(func(z *zInfo) { z.err = err.Error() })
		}
	}
	zSet(func(z *zInfo) { z.running, z.warpOn = false, false })
}

func (a *App) warpUp() {
	zSet(func(z *zInfo) { z.warpBusy, z.warpErr = true, "" })
	err := warpConnect()
	if err == errWarpCanceled {
		warpExec("disconnect")
		err = nil
		zSet(func(z *zInfo) { z.warpBusy, z.warpOn, z.warpErr = false, false, "" })
		return
	}
	zSet(func(z *zInfo) {
		z.warpBusy = false
		z.warpOn = err == nil
		if err != nil {
			z.warpErr = err.Error()
		}
	})
}

// Включить в текущем режиме.
func (a *App) modeOn() error {
	fallbackReset()
	defer func() { go a.rememberOn(a.anyOnSoon()) }()
	if a.mode() == "zapret" {
		return a.zapretOn()
	}
	if zapretSupported && winwsRunning() {
		a.zapretOff()
	}
	// ядро VPN могло быть остановлено в режиме запрета — запускаем и ждём готовности
	a.ensureCore()
	for i := 0; i < 30; i++ {
		if _, ready := a.powerState(); ready {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	return a.powerOn()
}

// Выключить всё.
func (a *App) allOff() {
	fallbackReset()
	defer a.rememberOn(false)
	a.powerOff()
	if zapretSupported {
		a.zapretOff()
	}
}

func (a *App) anyOn() bool {
	a.mu.Lock()
	on := a.on
	a.mu.Unlock()
	zi.mu.Lock()
	defer zi.mu.Unlock()
	return on || zi.running
}

func (a *App) zapretView() map[string]any {
	zi.mu.Lock()
	z := zi.zData
	zi.mu.Unlock()
	a.mu.Lock()
	strategy, warpWant := a.settings.ZStrategy, a.settings.Warp
	a.mu.Unlock()
	if !zapretSupported {
		return map[string]any{"supported": false}
	}
	st := readZState()
	results := map[string]zResult{}
	for _, r := range st.Results {
		results[r.Name] = r
	}
	type sv struct {
		File  string `json:"file"`
		Title string `json:"title"`
		OK    int    `json:"ok"`
		Of    int    `json:"of"`
		Ms    int    `json:"ms"`
	}
	var list []sv
	for _, f := range listStrategies(zapretDir()) {
		r := results[f]
		list = append(list, sv{f, strategyTitle(f), r.OK, r.Of, r.Ms})
	}
	testing := z.busy && st.Busy && st.Phase == "test"
	return map[string]any{
		"supported": true, "installed": zapretInstalled(), "version": zapretVersionOf(zapretDir()), "latest": z.latest,
		"running": z.running, "strategy": strategy, "strategyTitle": strategyTitle(strategy), "strategies": list,
		"busy": z.busy, "busyText": z.busyText, "error": z.err,
		"testing": testing, "done": st.Done, "total": st.Total, "current": st.Current,
		"warp": map[string]any{"installed": z.warpInst, "on": z.warpOn, "want": warpWant, "busy": z.warpBusy || z.warpInstalling,
			"error": z.warpErr, "installing": z.warpInstalling, "stage": warpStage.Load(), "phase": st.Phase, "mb": st.Done, "mbTotal": st.Total},
	}
}

var errNoZapretMsg = fmt.Errorf("запрет доступен только на Windows")

func (a *App) modeRoutes(m *http.ServeMux) {
	body := func(r *http.Request, v any) { json.NewDecoder(r.Body).Decode(v) }
	m.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Mode string }
		body(r, &req)
		if req.Mode != "zapret" {
			req.Mode = "vpn"
		}
		wasOn := a.anyOn()
		a.mu.Lock()
		changed := a.settings.Mode != req.Mode
		a.settings.Mode = req.Mode
		a.saveSettings()
		a.mu.Unlock()
		if changed && wasOn {
			go func() {
				if err := a.modeOn(); err != nil {
					a.setStatus("", err.Error())
				}
			}()
		} else if changed {
			go func() {
				fallbackReset()
				if req.Mode == "zapret" && !a.consoleWantsCore() {
					stopCore()
					a.mu.Lock()
					a.cur = -1
					a.status = "В режиме запрета VPN не запущен"
					a.mu.Unlock()
				} else {
					if zapretSupported && winwsRunning() {
						a.zapretOff()
					}
					a.ensureCore()
				}
			}()
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/zapret/strategy", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ File string }
		body(r, &req)
		a.mu.Lock()
		a.settings.ZStrategy = req.File
		a.saveSettings()
		warp := a.settings.Warp
		a.mu.Unlock()
		if winwsRunning() && !a.zapretBusy() {
			go func() {
				zSet(func(z *zInfo) { z.busy, z.busyText, z.err = true, "Перезапускаю запрет…", "" })
				_, err := zapretRun(zCmd{Action: "start", Strategy: req.File, Warp: warp}, 25*time.Second)
				zSet(func(z *zInfo) {
					z.busy = false
					if err != nil {
						z.err = err.Error()
					}
				})
			}()
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/zapret/test", func(w http.ResponseWriter, r *http.Request) {
		if a.zapretBusy() {
			writeJSON(w, map[string]any{"ok": false, "error": "запрет занят"})
			return
		}
		a.powerOff()
		a.mu.Lock()
		warp := a.settings.Warp
		a.settings.Mode = "zapret"
		a.saveSettings()
		a.mu.Unlock()
		go func() {
			zSet(func(z *zInfo) { z.busy, z.err = true, "" })
			defer zSet(func(z *zInfo) { z.busy = false })
			if !zapretInstalled() {
				zSet(func(z *zInfo) { z.busyText = "Скачиваю запрет…" })
				if _, err := zapretRun(zCmd{Action: "update"}, 5*time.Minute); err != nil {
					zSet(func(z *zInfo) { z.err = err.Error() })
					return
				}
			}
			a.zapretTestSync(warp)
			zSet(func(z *zInfo) { z.running = winwsRunning() })
		}()
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/zapret/update", func(w http.ResponseWriter, r *http.Request) {
		go a.zapretCheckUpdate(true)
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/warp", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ On bool }
		body(r, &req)
		a.mu.Lock()
		a.settings.Warp = req.On
		a.saveSettings()
		strategy := a.settings.ZStrategy
		a.mu.Unlock()
		if strategy == "" {
			strategy = readZState().Best
		}
		if req.On && warpCLI() == "" {
			go func() {
				if a.warpInstallSync() && winwsRunning() {
					zapretRun(zCmd{Action: "start", Strategy: strategy, Warp: true}, 25*time.Second)
					a.warpUp()
				}
			}()
			writeJSON(w, map[string]any{"ok": true})
			return
		}
		go func() {
			if !winwsRunning() {
				if !req.On {
					warpDisconnect()
				}
				return
			}
			if req.On {
				zSet(func(z *zInfo) { z.warpBusy, z.warpErr = true, "" })
				// перезапуск запрета с профилем для WARP
				if strategy != "" {
					if _, err := zapretRun(zCmd{Action: "start", Strategy: strategy, Warp: true}, 25*time.Second); err != nil {
						zSet(func(z *zInfo) { z.warpBusy, z.warpErr = false, err.Error() })
						return
					}
				}
				a.warpUp()
			} else {
				warpDisconnect()
				zSet(func(z *zInfo) { z.warpOn = false })
				if strategy != "" {
					zapretRun(zCmd{Action: "start", Strategy: strategy, Warp: false}, 25*time.Second)
				}
			}
		}()
		writeJSON(w, map[string]any{"ok": true})
	})
}

func init() { _ = log.Println }

// ---------- установка и обновление WARP ----------
func (a *App) warpInstallSync() bool {
	zi.mu.Lock()
	if zi.warpInstalling {
		zi.mu.Unlock()
		return false
	}
	zi.warpInstalling, zi.warpErr = true, ""
	zi.mu.Unlock()
	_, err := zapretRun(zCmd{Action: "warp-install"}, 25*time.Minute)
	inst := warpCLI() != ""
	if inst {
		warpGUIStart()
	}
	zSet(func(z *zInfo) {
		z.warpInstalling, z.warpInst = false, inst
		if err != nil {
			z.warpErr = err.Error()
		}
	})
	if err == nil {
		a.mu.Lock()
		a.event = time.Now().Format("15:04") + " — Cloudflare WARP установлен"
		a.mu.Unlock()
	}
	return err == nil && inst
}

func (a *App) warpUpdater() {
	if !zapretSupported {
		return
	}
	time.Sleep(40 * time.Second)
	// галочка «Установить WARP» в установщике
	warpGUIStart() // значок WARP в трее вместе с нашим
	pending := filepath.Join(dataDir, "pending-warp-install")
	if _, err := os.Stat(pending); err == nil {
		os.Remove(pending)
		a.mu.Lock()
		a.saveSettings() // WARP только устанавливаем; включает его пользователь сам
		a.mu.Unlock()
		if warpCLI() == "" {
			a.warpInstallSync()
		}
	}
	for {
		if warpCLI() != "" {
			latest, key, err := warpLatest()
			if err == nil {
				cur := warpVersion()
				saved, _ := os.ReadFile(filepath.Join(dataDir, "warp-release.txt"))
				need := false
				if latest != "" && cur != "" {
					need = versionNewer(latest, cur)
				} else if len(saved) > 0 {
					need = string(saved) != key
				}
				if need {
					zi.mu.Lock()
					wasOn := zi.warpOn
					zi.mu.Unlock()
					log.Printf("обновляю WARP %s -> %s", cur, latest)
					if a.warpInstallSync() && wasOn {
						a.warpUp()
					}
				}
			}
		}
		time.Sleep(12 * time.Hour)
	}
}

// ---------- точка доступа ----------
func (a *App) hotspotInit() {
	if !hotspotSupported {
		return
	}
	for {
		zi.mu.Lock()
		on, busy := zi.hsOn, zi.hsBusy
		zi.mu.Unlock()
		zi.mu.Lock()
		lanMode := zi.hsLAN
		zi.mu.Unlock()
		if on && !busy && !lanMode {
			if s, err := hotspotPS("status"); err == nil {
				zSet(func(z *zInfo) { z.hsInfo = s })
				if s.State == "Off" { // выключили из параметров Windows
					hotspotProxyStop()
					zSet(func(z *zInfo) { z.hsOn = false })
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
}

func hotspotShutdown() {
	zi.mu.Lock()
	on := zi.hsOn
	zi.mu.Unlock()
	if on {
		hotspotProxyStop()
		hotspotPS("stop")
	}
}

func (a *App) hotspotSet(on bool) {
	zSet(func(z *zInfo) { z.hsBusy, z.hsErr = true, "" })
	defer zSet(func(z *zInfo) { z.hsBusy = false })
	if !on {
		hotspotProxyStop()
		consoleStop()
		zi.mu.Lock()
		lanMode := zi.hsLAN
		zi.mu.Unlock()
		if lanMode {
			zSet(func(z *zInfo) { z.hsOn, z.hsLAN, z.hsNote = false, false, "" })
			return
		}
		s, err := hotspotPS("stop")
		zSet(func(z *zInfo) {
			z.hsOn, z.hsInfo = false, s
			if err != nil {
				z.hsErr = err.Error()
			}
		})
		return
	}
	a.mu.Lock()
	fw := a.settings.FirewallOK
	a.mu.Unlock()
	if !fw { // разрешить телефонам подключаться к прокси (один раз)
		if _, err := zapretRun(zCmd{Action: "firewall"}, 30*time.Second); err == nil {
			a.mu.Lock()
			a.settings.FirewallOK = true
			a.saveSettings()
			a.mu.Unlock()
		} else {
			log.Println("firewall:", err)
		}
	}
	a.mu.Lock()
	preferLAN := a.settings.ShareLAN
	a.mu.Unlock()
	if !preferLAN {
		s, err := hotspotPS("start")
		if err == nil {
			if err := hotspotProxyStart(false); err != nil {
				zSet(func(z *zInfo) { z.hsErr = err.Error() })
			}
			zSet(func(z *zInfo) { z.hsOn, z.hsLAN, z.hsInfo, z.hsNote = true, false, s, "" })
			a.consoleSync()
			go a.gatewaySync()
			return
		}
		log.Println("Wi-Fi раздача недоступна:", err)
		zSet(func(z *zInfo) {
			z.hsNote = "Wi-Fi точку доступа этот компьютер не поддерживает (" + err.Error() + ") — раздаю в локальную сеть."
		})
	}
	// раздача в локальную сеть (по проводу / через роутер)
	if err := hotspotProxyStart(true); err != nil {
		zSet(func(z *zInfo) { z.hsErr = err.Error() })
		return
	}
	zSet(func(z *zInfo) { z.hsOn, z.hsLAN, z.hsInfo = true, true, hsState{} })
	a.consoleSync()
	go a.gatewaySync()
}

var consoleFirewallOnce sync.Once

// Нужен ли VPN-сервер приставкам: режим приставок включён и раздача идёт.
func (a *App) consoleWantsCore() bool {
	a.mu.Lock()
	want := a.settings.ShareCons || a.settings.Gateway
	a.mu.Unlock()
	zi.mu.Lock()
	on := zi.hsOn
	zi.mu.Unlock()
	return want && on
}

// Режим для приставок: включён в настройках и раздача идёт — поднимаем DNS + SNI-прокси.
func (a *App) consoleSync() {
	a.mu.Lock()
	want := a.settings.ShareCons
	a.mu.Unlock()
	zi.mu.Lock()
	on, lan := zi.hsOn, zi.hsLAN
	zi.mu.Unlock()
	a.consoleCoreSync()
	if !want || !on {
		consoleStop()
		return
	}
	consoleFirewallOnce.Do(func() { // правила для портов приставок (один запрос через задачу запрета)
		if _, err := zapretRun(zCmd{Action: "firewall"}, 40*time.Second); err != nil {
			log.Println("firewall:", err)
		}
	})
	if lan {
		consoleStart(lanIP())
	} else {
		consoleStart(hotspotIP(), lanIP())
	}
}

var coreStarting atomic.Bool

// Ядро VPN для приставок: в режиме запрета оно поднимается без системного прокси —
// компьютер остаётся на запрете, а через VPN идёт только вход Xbox (и трафик шлюза по выбору).
func (a *App) consoleCoreSync() {
	if !a.consoleWantsCore() {
		if a.mode() == "zapret" && !a.fallbackActive() && coreRunning() {
			a.mu.Lock()
			vpn := a.on
			a.mu.Unlock()
			if !vpn {
				stopCore()
			}
		}
		return
	}
	if coreRunning() || !coreStarting.CompareAndSwap(false, true) {
		return
	}
	a.mu.Lock()
	servers := append([]*Server(nil), a.servers...)
	a.mu.Unlock()
	go func() {
		defer coreStarting.Store(false)
		if len(servers) > 0 {
			a.loadMu.Lock()
			a.applyServers(servers)
			a.loadMu.Unlock()
		} else {
			a.loadServers()
			a.mu.Lock()
			servers = append([]*Server(nil), a.servers...)
			a.mu.Unlock()
		}
		// запрет не должен трогать соединения с VPN-серверами — обновляем его исключения
		vpnServerIPs = resolveServerIPs(servers)
		a.mu.Lock()
		strategy, warp := a.settings.ZStrategy, a.settings.Warp
		a.mu.Unlock()
		if zapretSupported && winwsRunning() && !a.zapretBusy() && strategy != "" {
			zapretRun(zCmd{Action: "start", Strategy: strategy, Warp: warp}, 25*time.Second)
		}
		time.Sleep(20 * time.Second) // не перезапускать чаще
	}()
}

func (a *App) hotspotView() map[string]any {
	if !hotspotSupported {
		return map[string]any{"supported": false}
	}
	preferLAN := a.settingsShareLAN()
	cip, cerr, cq := consoleAddr()
	consOn := a.settingsConsole()
	var gv map[string]any
	if consOn {
		gv = a.geoView()
	}
	gwv := a.gatewayView() // до блокировки zi.mu: внутри она берётся снова (иначе взаимная блокировка)
	pxy := hotspotProxyAddr()
	zi.mu.Lock()
	defer zi.mu.Unlock()
	return map[string]any{"supported": true, "on": zi.hsOn, "busy": zi.hsBusy, "error": zi.hsErr,
		"lan": zi.hsLAN, "note": zi.hsNote, "preferLan": preferLAN,
		"ssid": zi.hsInfo.Ssid, "pass": zi.hsInfo.Pass, "clients": zi.hsInfo.Clients, "proxy": pxy,
		"console": consOn, "dns": cip, "dnsErr": cerr, "dnsQ": cq, "dns2": routerGuess(cip), "geo": gv, "gw": gwv}
}

func (a *App) settingsConsole() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings.ShareCons
}

func (a *App) settingsShareLAN() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings.ShareLAN
}

func cleanDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	if i := strings.IndexAny(d, "/:?#"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimPrefix(strings.TrimPrefix(d, "*."), "www.")
	return strings.Trim(d, ".")
}

func (a *App) extraRoutes(m *http.ServeMux) {
	m.HandleFunc("/api/hotspot", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ On bool }
		json.NewDecoder(r.Body).Decode(&req)
		go a.hotspotSet(req.On)
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		tail := func(name string, n int) string {
			b, err := os.ReadFile(filepath.Join(dataDir, name))
			if err != nil {
				return ""
			}
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			if len(lines) > n {
				lines = lines[len(lines)-n:]
			}
			return strings.Join(lines, "\n")
		}
		writeJSON(w, map[string]any{"app": tail("app.log", 40), "core": tail("core.log", 40), "zapret": tail("zapret.log", 30)})
	})
	m.HandleFunc("/api/openlogs", func(w http.ResponseWriter, r *http.Request) {
		openFolder(dataDir)
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/tgws", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ On bool }
		json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		a.settings.TgOn = req.On
		a.saveSettings()
		a.mu.Unlock()
		go a.tgwsSet(req.On)
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/tgws/telegram", func(w http.ResponseWriter, r *http.Request) {
		link := tgwsLink()
		if link != "" {
			openURL(link)
		}
		writeJSON(w, map[string]any{"ok": link != "", "link": link})
	})
	m.HandleFunc("/api/zextra", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ List []string }
		json.NewDecoder(r.Body).Decode(&req)
		list, seen := []string{}, map[string]bool{}
		for _, d := range req.List {
			if d = cleanDomain(d); d != "" && strings.Contains(d, ".") && !seen[d] {
				seen[d] = true
				list = append(list, d)
			}
		}
		a.mu.Lock()
		a.settings.ZExtra = list
		a.saveSettings()
		zapretExtra = append([]string{}, list...)
		strategy, warp := a.settings.ZStrategy, a.settings.Warp
		a.mu.Unlock()
		if zapretSupported && winwsRunning() && !a.zapretBusy() && strategy != "" {
			go zapretRun(zCmd{Action: "start", Strategy: strategy, Warp: warp}, 25*time.Second)
		}
		writeJSON(w, map[string]any{"ok": true, "list": list})
	})
	m.HandleFunc("/api/defender", func(w http.ResponseWriter, r *http.Request) {
		var err error
		if zapretTaskExists() {
			_, err = zapretRun(zCmd{Action: "defender"}, 60*time.Second)
		} else {
			exe, _ := os.Executable()
			ps := `Start-Process -FilePath ` + psQuote(exe) + ` -ArgumentList '--defender' -Verb RunAs -Wait`
			if e := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run(); e != nil {
				err = errors.New("нужно разрешение администратора")
			}
		}
		if err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/gateway", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			On       *bool
			GamesVPN *bool
		}
		json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		if req.On != nil {
			a.settings.Gateway = *req.On
			gwMgr.Lock()
			gwMgr.fails, gwMgr.err, gwMgr.lastTry = 0, "", time.Time{} // заново — новые попытки
			gwMgr.Unlock()
		}
		if req.GamesVPN != nil {
			a.settings.GwGamesVPN = *req.GamesVPN
		}
		a.saveSettings()
		a.mu.Unlock()
		go a.gatewaySync()
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/shareconsole", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Value bool }
		json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		a.settings.ShareCons = req.Value
		a.saveSettings()
		a.mu.Unlock()
		go a.consoleSync()
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/sharelan", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Value bool }
		json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		a.settings.ShareLAN = req.Value
		a.saveSettings()
		a.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/bypass", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ List []string }
		json.NewDecoder(r.Body).Decode(&req)
		list := []string{}
		seen := map[string]bool{}
		for _, d := range req.List {
			if d = cleanDomain(d); d != "" && strings.Contains(d, ".") && !seen[d] {
				seen[d] = true
				list = append(list, d)
			}
		}
		a.mu.Lock()
		a.settings.Bypass = list
		a.saveSettings()
		bypassList = append([]string{}, list...)
		on, servers, strategy, warp := a.on, a.servers, a.settings.ZStrategy, a.settings.Warp
		a.mu.Unlock()
		go func() {
			if on {
				setSysProxy(true)
			}
			if len(servers) > 0 {
				a.loadMu.Lock()
				a.applyServers(servers)
				a.loadMu.Unlock()
			}
			if zapretSupported && winwsRunning() && !a.zapretBusy() {
				zapretRun(zCmd{Action: "start", Strategy: strategy, Warp: warp}, 25*time.Second)
			}
			if warpCLI() != "" {
				warpExclude()
			}
		}()
		writeJSON(w, map[string]any{"ok": true, "list": list})
	})
}

// ---------- TG WS Proxy ----------
func (a *App) tgwsSet(on bool) {
	zSet(func(z *zInfo) { z.tgBusy, z.tgErr = true, "" })
	defer zSet(func(z *zInfo) { z.tgBusy = false })
	if !on {
		tgwsStop()
		zSet(func(z *zInfo) { z.tgRunning = false })
		return
	}
	if !tgwsInstalled() {
		v, err := tgwsInstall()
		if err != nil {
			zSet(func(z *zInfo) { z.tgErr = err.Error() })
			return
		}
		zSet(func(z *zInfo) { z.tgInstalled, z.tgVersion = true, v })
	}
	if err := tgwsStart(); err != nil {
		zSet(func(z *zInfo) { z.tgErr = err.Error() })
		return
	}
	zSet(func(z *zInfo) { z.tgRunning = true })
}

// наблюдение, восстановление после перезапуска, установка из установщика и обновления
func (a *App) tgwsLoop() {
	if !tgwsSupported {
		return
	}
	upd := time.Now().Add(30 * time.Second)
	pending := filepath.Join(dataDir, "pending-tgws-install")
	if _, err := os.Stat(pending); err == nil {
		os.Remove(pending)
		a.mu.Lock()
		a.settings.TgOn = true
		a.saveSettings()
		a.mu.Unlock()
	}
	a.mu.Lock()
	want, vpn := a.settings.TgOn, a.on
	a.mu.Unlock()
	if want && !vpn {
		a.tgwsSet(true)
	}
	for {
		run, inst := tgwsRunning(), tgwsInstalled()

		zSet(func(z *zInfo) { z.tgRunning, z.tgInstalled, z.tgVersion = run, inst, tgwsLocalVersion() })
		if inst && time.Now().After(upd) {
			upd = time.Now().Add(12 * time.Hour)
			tag, err := tgwsLatestTag()
			if err == nil && tag != "" && tgwsLocalVersion() == "embedded" {
				// копия из установщика считается актуальной на момент сборки — только запоминаем версию
				os.WriteFile(filepath.Join(tgwsDir(), "version.txt"), []byte(tag), 0644)
			} else if err == nil && tag != "" && tag != tgwsLocalVersion() {
				log.Println("обновляю TG WS Proxy до", tag)
				if v, err := tgwsInstall(); err == nil {
					a.mu.Lock()
					a.event = time.Now().Format("15:04") + " — TG WS Proxy обновлён до " + v
					a.mu.Unlock()
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func (a *App) tgwsView() map[string]any {
	if !tgwsSupported {
		return map[string]any{"supported": false}
	}
	zi.mu.Lock()
	defer zi.mu.Unlock()
	return map[string]any{"supported": true, "installed": zi.tgInstalled, "on": zi.tgRunning, "busy": zi.tgBusy,
		"error": zi.tgErr, "version": zi.tgVersion}
}

// после асинхронного включения запрета состояние появляется не сразу
func (a *App) anyOnSoon() bool {
	for i := 0; i < 60; i++ {
		if a.anyOn() {
			return true
		}
		if !a.zapretBusy() && i > 4 {
			break
		}
		time.Sleep(time.Second)
	}
	return a.anyOn()
}
