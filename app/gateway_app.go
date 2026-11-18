package main

// Управление режимом шлюза из программы: настройки для процесса шлюза, запуск/остановка, вид в окне.

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var gwActive atomic.Bool

var gwMgr = struct {
	sync.Mutex
	running  bool
	ifIdx    int
	err      string
	starting bool      // идёт запуск (не блокируем остальное)
	lastTry  time.Time // не чаще раза в минуту
	fails    int       // подряд неудачных запусков — после 3 перестаём, пока не переключат заново
}{}

func (a *App) settingsGateway() (on, games bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings.Gateway, a.settings.GwGamesDirect
}

func ifIndexOf(ip string) int {
	ifs, _ := net.Interfaces()
	for _, in := range ifs {
		addrs, _ := in.Addrs()
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok && ipn.IP.String() == ip {
				return in.Index
			}
		}
	}
	return 0
}

// Адрес компьютера, который приставка указывает шлюзом.
func gatewayIP() string {
	zi.mu.Lock()
	lan := zi.hsLAN
	zi.mu.Unlock()
	if !lan {
		if ip := hotspotIP(); ip != "" {
			return ip
		}
	}
	return lanIP()
}

func (a *App) gwBuildConfig(pc string, ifIdx int) gwConfig {
	_, games := a.settingsGateway()
	c := gwConfig{On: true, PC: pc, IfIdx: ifIdx, Mode: "direct", Bypass: append([]string{}, bypassList...), GamesDir: games, TS: time.Now().Unix()}
	if coreRunning() {
		a.mu.Lock()
		vpn, cur := a.on, a.cur
		var order []int
		if cur >= 0 && cur < len(a.servers) && a.servers[cur].Ping > 0 {
			order = append(order, cur)
		}
		for i, s := range a.servers {
			if i != cur && s.Ping > 0 && s.Kind == "" && len(order) < 4 {
				order = append(order, i)
			}
		}
		a.mu.Unlock()
		if vpn {
			c.Mode = "vpn"
			for _, i := range order {
				c.HTTP = append(c.HTTP, basePort+i)
				c.Socks = append(c.Socks, socksBase+i)
			}
		}
		for _, r := range a.geoRoutes() {
			if r.idx >= 0 && len(c.GeoHTTP) < 4 {
				c.GeoHTTP = append(c.GeoHTTP, basePort+r.idx)
				c.GeoSocks = append(c.GeoSocks, socksBase+r.idx)
			}
		}
	}
	return c
}

func writeGWConfig(c gwConfig) {
	b, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(gwConfigPath(), b, 0644)
}

// Привести шлюз в соответствие настройкам (вызывается при изменениях и раз в 2 секунды).
func (a *App) gatewaySync() {
	if !gatewaySupported {
		return
	}
	want, _ := a.settingsGateway()
	zi.mu.Lock()
	hs := zi.hsOn
	zi.mu.Unlock()
	gwMgr.Lock()
	running, ifIdx := gwMgr.running, gwMgr.ifIdx
	gwMgr.Unlock()
	if !want || !hs {
		gwActive.Store(false)
		if running {
			writeGWConfig(gwConfig{On: false, TS: time.Now().Unix()})
			go zapretRun(zCmd{Action: "gateway-off", IfIdx: ifIdx}, 30*time.Second)
			gwMgr.Lock()
			gwMgr.running, gwMgr.err, gwMgr.fails = false, "", 0
			gwMgr.Unlock()
		}
		return
	}
	gwActive.Store(true)
	pc := gatewayIP()
	if pc == "" {
		gwMgr.Lock()
		gwMgr.err = "не найден адрес компьютера в сети"
		gwMgr.Unlock()
		return
	}
	idx := ifIndexOf(pc)
	writeGWConfig(a.gwBuildConfig(pc, idx))
	st := readGWState()
	alive := st.PID > 0 && st.Err == "" && time.Since(time.Unix(st.TS, 0)) < 8*time.Second
	if alive && st.Clients != "" {
		for _, ip := range strings.Split(st.Clients, ",") {
			devSeen(strings.TrimSpace(ip), "шлюз", false)
		}
	}
	gwMgr.Lock()
	gwMgr.running, gwMgr.ifIdx = true, idx
	if st.Err != "" {
		gwMgr.err = st.Err
	}
	canTry := !alive && !gwMgr.starting && gwMgr.fails < 3 && time.Since(gwMgr.lastTry) > time.Minute
	if alive {
		gwMgr.fails, gwMgr.err = 0, ""
	}
	if canTry {
		gwMgr.starting, gwMgr.lastTry = true, time.Now()
	}
	gwMgr.Unlock()
	if canTry {
		go func() { // запуск — в фоне, чтобы ничего не ждало задачу администратора
			_, err := zapretRun(zCmd{Action: "gateway", IfIdx: idx}, 40*time.Second)
			time.Sleep(4 * time.Second)
			s := readGWState()
			ok := err == nil && s.PID > 0 && s.Err == "" && time.Since(time.Unix(s.TS, 0)) < 8*time.Second
			gwMgr.Lock()
			gwMgr.starting = false
			if !ok {
				gwMgr.fails++
				if err != nil {
					gwMgr.err = err.Error()
				} else if s.Err != "" {
					gwMgr.err = s.Err
				} else if gwMgr.err == "" {
					gwMgr.err = "шлюз не запустился"
				}
				log.Println("шлюз:", gwMgr.err)
			}
			gwMgr.Unlock()
		}()
	}
	// для входа Xbox нужны страны серверов и (в режиме запрета) работающее ядро
	go a.geoLoop()
	a.consoleCoreSync()
}

func (a *App) gatewayLoop() {
	for {
		time.Sleep(2 * time.Second)
		on, _ := a.settingsGateway()
		gwMgr.Lock()
		running := gwMgr.running
		gwMgr.Unlock()
		if on || running {
			a.gatewaySync()
		}
	}
}

func (a *App) gatewayView() map[string]any {
	on, games := a.settingsGateway()
	v := map[string]any{"supported": gatewaySupported, "on": on, "games": games}
	if !on {
		return v
	}
	st := readGWState()
	gwMgr.Lock()
	err := gwMgr.err
	gwMgr.Unlock()
	if st.Err != "" {
		err = st.Err
	}
	alive := st.PID > 0 && time.Since(time.Unix(st.TS, 0)) < 8*time.Second
	v["running"], v["err"], v["clients"] = alive, err, st.Clients
	v["mb"] = float64(st.TCP+st.UDP) / 1e6
	pc := gatewayIP()
	v["pc"] = pc
	if r := routerGuess(pc); r != "" {
		v["router"] = r
	}
	return v
}
