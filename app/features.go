package main

// Дополнительные функции: резерв на запрет, автозапуск, уведомления, горячая клавиша,
// несколько подписок, тест скорости, график пинга, правила по сети и расписание, QR.

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Profile struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type Rules struct {
	NetEnabled bool     `json:"netEnabled"`
	Home       []string `json:"home"`
	HomeMode   string   `json:"homeMode"`  // vpn | zapret | off | keep
	OtherMode  string   `json:"otherMode"` // vpn | zapret | off | keep
	SchedOn    bool     `json:"schedOn"`
	OnAt       string   `json:"onAt"`  // ЧЧ:ММ
	OffAt      string   `json:"offAt"` // ЧЧ:ММ
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
func bptr(b bool) *bool { return &b }

func (a *App) optNotify() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return boolOr(a.settings.Notify, true)
}
func (a *App) optFallback() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return boolOr(a.settings.Fallback, true)
}
func (a *App) optHotkey() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return boolOr(a.settings.Hotkey, true)
}

// ---------- профили (несколько подписок) ----------
func (a *App) migrateProfiles() { // под a.mu
	if len(a.settings.Profiles) == 0 && a.settings.Key != "" {
		a.settings.Profiles = []Profile{{Name: "Основная", Key: a.settings.Key}}
		a.settings.Active = 0
	}
	if a.settings.Active >= len(a.settings.Profiles) {
		a.settings.Active = 0
	}
}

func cachePath(key string) string {
	h := sha1.Sum([]byte(key))
	return filepath.Join(dataDir, fmt.Sprintf("subscription-cache-%x.txt", h[:5]))
}

// ---------- уведомления о событиях ----------
func (a *App) notifier() {
	last := ""
	for {
		time.Sleep(time.Second)
		a.mu.Lock()
		ev := a.event
		a.mu.Unlock()
		if ev != "" && ev != last {
			last = ev
			if a.optNotify() {
				txt := ev
				if i := strings.Index(txt, " — "); i >= 0 && i < 8 {
					txt = txt[i+len(" — "):]
				}
				notify("NETtool", txt)
			}
		}
	}
}

func (a *App) setEvent(text string) {
	a.mu.Lock()
	a.event = time.Now().Format("15:04") + " — " + text
	a.mu.Unlock()
}

// ---------- резерв: VPN упал → запрет, VPN ожил → обратно ----------
var fb struct {
	sync.Mutex
	dead, alive int
	active      bool
}

func (a *App) fallbackActive() bool { fb.Lock(); defer fb.Unlock(); return fb.active }
func fallbackReset()                { fb.Lock(); fb.active, fb.dead, fb.alive = false, 0, 0; fb.Unlock() }

// вызывается после каждого раунда проверки серверов
func (a *App) checkFallback(alive, total int) {
	if !zapretSupported || total == 0 {
		return
	}
	a.mu.Lock()
	vpnOn := a.on
	a.mu.Unlock()
	fb.Lock()
	active := fb.active
	if alive == 0 {
		fb.dead++
		fb.alive = 0
	} else {
		fb.alive++
		fb.dead = 0
	}
	dead, back := fb.dead, fb.alive
	fb.Unlock()

	switch {
	case vpnOn && !active && dead >= 2 && a.optFallback() && !a.zapretBusy():
		log.Println("все VPN-серверы недоступны — переключаюсь на запрет")
		fb.Lock()
		fb.active = true
		fb.Unlock()
		a.powerOff()
		if err := a.zapretOn(); err != nil {
			a.setEvent("VPN недоступен, а запрет не включился: " + err.Error())
			return
		}
		a.setEvent("VPN недоступен — временно включён запрет")
	case active && back >= 2:
		log.Println("VPN снова доступен — возвращаю VPN")
		fallbackReset()
		a.zapretOff()
		if err := a.powerOn(); err == nil {
			a.setEvent("VPN снова работает — вернул VPN")
		}
	}
}

// ---------- автозапуск и восстановление последнего режима ----------
var autostartLaunch bool

func (a *App) restoreLastOn() {
	// при запуске вместе с Windows — всегда запрет и всегда без WARP
	if autostartLaunch && zapretSupported {
		a.mu.Lock()
		a.settings.Mode = "zapret"
		a.settings.Warp = false
		a.saveSettings()
		a.mu.Unlock()
		time.Sleep(3 * time.Second) // дать сети подняться после входа в систему
		for i := 0; i < 20; i++ {
			if err := a.zapretOn(); err == nil {
				a.setEvent("запрет включён автоматически при запуске")
				return
			}
			time.Sleep(3 * time.Second)
		}
		return
	}
	a.mu.Lock()
	want := a.settings.LastOn
	a.mu.Unlock()
	if !want {
		return
	}
	for i := 0; i < 90; i++ {
		if _, ready := a.powerState(); ready {
			if err := a.modeOn(); err == nil {
				a.setEvent("включено автоматически при запуске")
			}
			return
		}
		time.Sleep(time.Second)
	}
}

func (a *App) rememberOn(on bool) {
	a.mu.Lock()
	if a.settings.LastOn != on {
		a.settings.LastOn = on
		a.saveSettings()
	}
	a.mu.Unlock()
}

// ---------- история пинга ----------
func (a *App) recordHistory() { // под a.mu
	if a.hist == nil {
		a.hist = map[string][]int{}
	}
	for _, s := range a.servers {
		h := append(a.hist[s.Name], s.Ping)
		if len(h) > 60 {
			h = h[len(h)-60:]
		}
		a.hist[s.Name] = h
	}
}

// ---------- тест скорости ----------
const speedURL = "https://speed.cloudflare.com/__down?bytes=25000000"

func speedTest(i int) float64 {
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", basePort+i))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSHandshakeTimeout: 8 * time.Second}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	resp, err := cl.Get(speedURL)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	start := time.Now()
	buf := make([]byte, 64<<10)
	var n int64
	for time.Since(start) < 7*time.Second {
		k, err := resp.Body.Read(buf)
		n += int64(k)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}
	secs := time.Since(start).Seconds()
	if n < 100<<10 || secs <= 0 {
		return -1
	}
	return float64(n) * 8 / secs / 1e6
}

func (a *App) runSpeedTest() {
	a.mu.Lock()
	if a.speedBusy {
		a.mu.Unlock()
		return
	}
	a.speedBusy = true
	type cand struct {
		i    int
		name string
		ping int
	}
	var cs []cand
	for i, s := range a.servers {
		if s.Ping > 0 {
			cs = append(cs, cand{i, s.Name, s.Ping})
		}
	}
	gen := a.gen
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.speedBusy, a.speedDone, a.speedTotal = false, 0, 0; a.mu.Unlock() }()
	sort.Slice(cs, func(x, y int) bool { return cs[x].ping < cs[y].ping })
	if len(cs) > 8 {
		cs = cs[:8]
	}
	a.mu.Lock()
	a.speedTotal = len(cs)
	a.mu.Unlock()
	for k, c := range cs {
		mbps := speedTest(c.i)
		a.mu.Lock()
		if gen != a.gen {
			a.mu.Unlock()
			return
		}
		if a.speed == nil {
			a.speed = map[string]float64{}
		}
		a.speed[c.name] = mbps
		a.speedDone = k + 1
		if a.settings.AutoBy == "speed" {
			a.choose()
		}
		a.mu.Unlock()
	}
	a.setEvent("тест скорости завершён")
}

// ---------- правила по сети и расписание ----------
func (a *App) applyRuleMode(m string, why string) {
	switch m {
	case "off":
		if a.anyOn() {
			a.allOff()
			a.setEvent(why + ": выключено")
		}
	case "vpn", "zapret":
		if m == "zapret" && !zapretSupported {
			return
		}
		a.mu.Lock()
		changed := a.settings.Mode != m
		a.settings.Mode = m
		a.saveSettings()
		a.mu.Unlock()
		if changed || !a.anyOn() {
			if err := a.modeOn(); err == nil {
				name := map[string]string{"vpn": "VPN", "zapret": "запрет"}[m]
				a.setEvent(why + ": включён " + name)
			}
		}
	}
}

func (a *App) rulesLoop() {
	lastNet := "\x00"
	lastMin := ""
	for {
		time.Sleep(20 * time.Second)
		a.mu.Lock()
		r := a.settings.Rules
		a.mu.Unlock()
		if r.NetEnabled {
			n := currentNetwork()
			if n != "" && n != lastNet {
				first := lastNet == "\x00"
				lastNet = n
				home := false
				for _, h := range r.Home {
					if strings.EqualFold(strings.TrimSpace(h), n) {
						home = true
					}
				}
				m := r.OtherMode
				why := "чужая сеть «" + n + "»"
				if home {
					m, why = r.HomeMode, "домашняя сеть «"+n+"»"
				}
				if !(first && autostartLaunch && m == "keep") {
					a.applyRuleMode(m, why)
				}
			}
		}
		if r.SchedOn {
			now := time.Now().Format("15:04")
			if now != lastMin {
				lastMin = now
				if now == r.OnAt {
					a.applyRuleMode(a.mode(), "по расписанию")
				} else if now == r.OffAt {
					a.applyRuleMode("off", "по расписанию")
				}
			}
		}
	}
}

// ---------- API ----------
func (a *App) featureRoutes(m *http.ServeMux) {
	m.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&req)
		b := func(k string) (bool, bool) {
			v, ok := req[k]
			if !ok {
				return false, false
			}
			var x bool
			json.Unmarshal(v, &x)
			return x, true
		}
		s := func(k string) (string, bool) {
			v, ok := req[k]
			if !ok {
				return "", false
			}
			var x string
			json.Unmarshal(v, &x)
			return x, true
		}
		var autostart *bool
		var hotkey *bool
		a.mu.Lock()
		if v, ok := b("notify"); ok {
			a.settings.Notify = bptr(v)
		}
		if v, ok := b("fallback"); ok {
			a.settings.Fallback = bptr(v)
		}
		if v, ok := b("hotkey"); ok {
			a.settings.Hotkey = bptr(v)
			hotkey = bptr(v)
		}
		if v, ok := b("autostart"); ok {
			a.settings.Autostart = v
			autostart = bptr(v)
		}
		if v, ok := s("theme"); ok {
			a.settings.Theme = v
		}
		if v, ok := s("autoBy"); ok {
			a.settings.AutoBy = v
			a.choose()
		}
		if v, ok := req["rules"]; ok {
			var rr Rules
			if json.Unmarshal(v, &rr) == nil {
				a.settings.Rules = rr
			}
		}
		a.saveSettings()
		a.mu.Unlock()
		var errMsg string
		if autostart != nil {
			if err := setAutostart(*autostart); err != nil {
				errMsg = err.Error()
			}
		}
		if hotkey != nil {
			hotkeySet(*hotkey)
		}
		writeJSON(w, map[string]any{"ok": errMsg == "", "error": errMsg})
	})
	m.HandleFunc("/api/profiles", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action string
			Index  int
			Name   string
			Key    string
		}
		json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		p := a.settings.Profiles
		reload := false
		switch req.Action {
		case "add":
			if k := strings.TrimSpace(req.Key); k != "" {
				name := strings.TrimSpace(req.Name)
				if name == "" {
					name = fmt.Sprintf("Подписка %d", len(p)+1)
				}
				p = append(p, Profile{name, k})
				a.settings.Active = len(p) - 1
				reload = true
			}
		case "select":
			if req.Index >= 0 && req.Index < len(p) && req.Index != a.settings.Active {
				a.settings.Active = req.Index
				reload = true
			}
		case "delete":
			if req.Index >= 0 && req.Index < len(p) {
				os.Remove(cachePath(p[req.Index].Key))
				p = append(p[:req.Index:req.Index], p[req.Index+1:]...)
				if a.settings.Active >= len(p) {
					a.settings.Active = 0
				}
				reload = true
			}
		case "rename":
			if req.Index >= 0 && req.Index < len(p) && strings.TrimSpace(req.Name) != "" {
				p[req.Index].Name = strings.TrimSpace(req.Name)
			}
		}
		a.settings.Profiles = p
		if len(p) > 0 {
			a.settings.Key = p[a.settings.Active].Key
		} else {
			a.settings.Key = ""
		}
		a.settings.Pinned = ""
		a.saveSettings()
		key := a.settings.Key
		a.mu.Unlock()
		if reload {
			if key == "" {
				a.powerOff()
				stopCore()
				a.mu.Lock()
				a.servers, a.cfg, a.cur = nil, nil, -1
				a.gen++
				a.mu.Unlock()
				a.setStatus("Добавьте подписку, чтобы начать", "")
			} else {
				go a.loadServers()
			}
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/speedtest", func(w http.ResponseWriter, r *http.Request) {
		go a.runSpeedTest()
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/netname", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"name": currentNetwork()})
	})
	m.HandleFunc("/api/qr", func(w http.ResponseWriter, r *http.Request) {
		svg, err := qrSVG(r.URL.Query().Get("text"))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write([]byte(svg))
	})
	m.HandleFunc("/api/full", func(w http.ResponseWriter, r *http.Request) {
		go openOrFocusUI()
		writeJSON(w, map[string]any{"ok": true})
	})
}

// для окна: настройки и данные новых функций
func (a *App) featureView() map[string]any { // под a.mu
	var hist []int
	if a.cur >= 0 && a.cur < len(a.servers) {
		hist = a.hist[a.servers[a.cur].Name]
	}
	speeds := map[string]float64{}
	for k, v := range a.speed {
		speeds[k] = v
	}
	profiles := make([]map[string]any, len(a.settings.Profiles))
	for i, p := range a.settings.Profiles {
		profiles[i] = map[string]any{"name": p.Name, "hint": keyHint(p.Key)}
	}
	return map[string]any{
		"profiles": profiles, "active": a.settings.Active,
		"history": hist, "speeds": speeds, "speedBusy": a.speedBusy, "speedDone": a.speedDone, "speedTotal": a.speedTotal,
		"fallbackActive": fb.active,
		"opts": map[string]any{
			"notify": boolOr(a.settings.Notify, true), "fallback": boolOr(a.settings.Fallback, true),
			"hotkey": boolOr(a.settings.Hotkey, true), "hotkeySupported": hotkeySupported,
			"autostart": a.settings.Autostart, "theme": a.settings.Theme, "autoBy": a.settings.AutoBy,
			"rules": a.settings.Rules,
		},
	}
}

// ---------- автоматический тест скорости при проблемах с подключением ----------
// Если выбранный сервер не отвечает (или подключение не готово) дольше 15 секунд —
// программа сама проверяет скорость отвечающих серверов и переключается на самый быстрый.
func (a *App) connWatch() {
	var badSince, lastRun time.Time
	for {
		time.Sleep(3 * time.Second)
		a.mu.Lock()
		on := a.on
		bad := a.cur < 0 || a.cur >= len(a.servers) || a.servers[a.cur].Ping <= 0
		alive := 0
		for _, s := range a.servers {
			if s.Ping > 0 && s.Kind == "" {
				alive++
			}
		}
		busy := a.speedBusy
		a.mu.Unlock()
		if !on || !coreRunning() || !bad {
			badSince = time.Time{}
			continue
		}
		if badSince.IsZero() {
			badSince = time.Now()
			continue
		}
		if time.Since(badSince) < 15*time.Second || busy || alive == 0 || time.Since(lastRun) < 5*time.Minute {
			continue
		}
		lastRun = time.Now()
		log.Println("сервер не отвечает дольше 15 секунд — запускаю тест скорости")
		a.setEvent("сервер не отвечает — проверяю скорость остальных")
		a.runSpeedTest()
		a.mu.Lock()
		best := -1
		for i, s := range a.servers {
			if s.Ping > 0 && s.Kind == "" && a.speed[s.Name] > 0 && (best < 0 || a.speed[s.Name] > a.speed[a.servers[best].Name]) {
				best = i
			}
		}
		pinnedAlive := false
		for _, s := range a.servers {
			if s.Name == a.settings.Pinned && s.Ping > 0 {
				pinnedAlive = true
			}
		}
		if best >= 0 && !pinnedAlive && (a.cur < 0 || a.cur >= len(a.servers) || a.servers[a.cur].Ping <= 0) {
			a.cur = best
			a.event = fmt.Sprintf("%s — сервер не отвечал; по тесту скорости выбран «%s» (%.0f Мбит/с)",
				time.Now().Format("15:04"), a.servers[best].Name, a.speed[a.servers[best].Name])
			a.rememberCur()
		}
		a.mu.Unlock()
		badSince = time.Time{}
	}
}
