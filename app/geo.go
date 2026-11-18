package main

// Страна выхода: через какой сервер VPN (или напрямую — через WARP) интернет видит компьютер.
// Нужно для входа в Xbox: Microsoft не пускает российские адреса (0x80a40401), поэтому
// вход приставки ведём только через выход НЕ из России.

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const traceURL = "https://www.cloudflare.com/cdn-cgi/trace"

var geo = struct {
	sync.Mutex
	byServer  map[string]string    // имя сервера → страна (RU, NL, …)
	checked   map[string]time.Time // когда проверяли
	direct    string               // страна прямого выхода (через запрет/WARP)
	warp      bool                 // прямой выход идёт через WARP
	directAt  time.Time
	running   bool
	lastRoute string
}{byServer: map[string]string{}, checked: map[string]time.Time{}}

// Ответ Cloudflare trace: строки key=value; нужны loc и warp.
func parseTrace(body string) (loc string, warp bool) {
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "loc":
			loc = strings.ToUpper(strings.TrimSpace(v))
		case "warp":
			warp = strings.TrimSpace(v) == "on" || strings.TrimSpace(v) == "plus"
		}
	}
	return
}

func traceVia(tr *http.Transport) (string, bool, error) {
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := cl.Get(traceURL)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	loc, warp := parseTrace(string(b))
	if loc == "" {
		return "", false, fmt.Errorf("нет страны в ответе")
	}
	return loc, warp, nil
}

// Фоновая проверка стран (пока включён режим приставок).
func (a *App) geoLoop() {
	geo.Lock()
	if geo.running {
		geo.Unlock()
		return
	}
	geo.running = true
	geo.Unlock()
	defer func() { geo.Lock(); geo.running = false; geo.Unlock() }()
	for {
		if !coreRunning() && !gwActive.Load() {
			time.Sleep(20 * time.Second)
			continue
		}
		a.geoCheckOnce()
		time.Sleep(20 * time.Second)
	}
}

func (a *App) geoCheckOnce() {
	// прямой выход (через запрет/WARP) — раз в минуту: WARP могут включить или выключить
	geo.Lock()
	needDirect := time.Since(geo.directAt) > time.Minute
	geo.Unlock()
	if needDirect {
		loc, warp, err := traceVia(&http.Transport{Proxy: nil})
		geo.Lock()
		geo.directAt = time.Now()
		if err == nil {
			geo.direct, geo.warp = loc, warp
		} else {
			geo.direct, geo.warp = "", false
		}
		geo.Unlock()
	}
	if !coreRunning() {
		return
	}
	// серверы VPN: отвечающие, ещё не проверенные (или давно) — по 6 за раз
	a.mu.Lock()
	for _, s := range a.servers { // после обновления подписки — сразу по уже известным странам
		geo.Lock()
		c, has := geo.byServer[s.Name]
		geo.Unlock()
		if has && isCIS(c) && s.Kind == "" {
			s.Kind = "cis"
		}
	}
	if a.cur >= 0 && a.cur < len(a.servers) && a.servers[a.cur].Kind == "cis" && a.settings.Pinned != a.servers[a.cur].Name {
		a.choose()
	}
	type cand struct {
		i    int
		name string
	}
	var list []cand
	for i, s := range a.servers {
		if s.Ping <= 0 || s.Kind != "" {
			continue
		}
		geo.Lock()
		at := geo.checked[s.Name]
		geo.Unlock()
		if time.Since(at) > 30*time.Minute {
			list = append(list, cand{i, s.Name})
		}
	}
	gen := a.gen
	a.mu.Unlock()
	if len(list) > 6 {
		list = list[:6]
	}
	var wg sync.WaitGroup
	for _, c := range list {
		wg.Add(1)
		go func(c cand) {
			defer wg.Done()
			pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", basePort+c.i))
			tr := &http.Transport{Proxy: http.ProxyURL(pu)}
			defer tr.CloseIdleConnections()
			loc, _, err := traceVia(tr)
			a.mu.Lock()
			stale := gen != a.gen
			a.mu.Unlock()
			if stale {
				return
			}
			geo.Lock()
			geo.checked[c.name] = time.Now()
			if err == nil {
				geo.byServer[c.name] = loc
			}
			geo.Unlock()
			if err == nil && isCIS(loc) { // фактический выход в СНГ — убираем из автовыбора
				a.mu.Lock()
				if c.i < len(a.servers) && a.servers[c.i].Name == c.name && a.servers[c.i].Kind == "" {
					a.servers[c.i].Kind = "cis"
					if a.cur == c.i && a.settings.Pinned != c.name {
						a.choose()
					}
				}
				a.mu.Unlock()
			}
		}(c)
	}
	wg.Wait()
}

// Похоже по названию, что сервер выходит в России («обход белых списков» и т.п.).
func looksRussian(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"обход", "🇷🇺", "росси", "russia", "moscow", "москв", " ru ", "[ru]", "ru-", "спб", "питер"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

type geoRoute struct {
	idx     int    // сервер VPN; -1 — напрямую
	name    string // для показа
	country string
	ok      bool // выход не из России (или страна неизвестна, но похоже, что не из России)
}

// Варианты выхода для входа в Xbox по порядку: проверенные зарубежные серверы (по пингу),
// затем непроверенные, но не «российские» по названию, затем прямой выход, если это WARP/не Россия.
func (a *App) geoRoutes() []geoRoute {
	var out []geoRoute
	if coreRunning() {
		a.mu.Lock()
		type sv struct {
			i    int
			name string
			ping int
		}
		var known, unknown []sv
		for i, s := range a.servers {
			if s.Ping <= 0 || s.Kind != "" {
				continue
			}
			geo.Lock()
			c, has := geo.byServer[s.Name]
			geo.Unlock()
			switch {
			case has && !isCIS(c):
				known = append(known, sv{i, s.Name, s.Ping})
			case !has && !looksRussian(s.Name):
				unknown = append(unknown, sv{i, s.Name, s.Ping})
			}
		}
		a.mu.Unlock()
		byPing := func(l []sv) { sort.Slice(l, func(x, y int) bool { return l[x].ping < l[y].ping }) }
		byPing(known)
		byPing(unknown)
		for _, s := range known {
			geo.Lock()
			c := geo.byServer[s.name]
			geo.Unlock()
			out = append(out, geoRoute{s.i, s.name, c, true})
		}
		for _, s := range unknown {
			out = append(out, geoRoute{s.i, s.name, "", true})
		}
	}
	geo.Lock()
	d, w := geo.direct, geo.warp
	geo.Unlock()
	if d != "" && !isCIS(d) {
		name := "напрямую"
		if w {
			name = "WARP"
		}
		out = append(out, geoRoute{-1, name, d, true})
	}
	return out
}

// Соединение для входа в Xbox: перебираем зарубежные выходы.
func (a *App) dialGeo(target string) (net.Conn, error) {
	routes := a.geoRoutes()
	tries := 0
	for _, r := range routes {
		if tries >= 5 {
			break
		}
		tries++
		var c net.Conn
		var err error
		if r.idx < 0 {
			c, err = net.DialTimeout("tcp", target, 10*time.Second)
		} else {
			c, err = dialViaCore(r.idx, target)
		}
		if err == nil {
			log.Printf("зарубежный выход: %s → %s %s", target, r.name, r.country)
			geo.Lock()
			geo.lastRoute = r.name
			if r.country != "" {
				geo.lastRoute += " (" + r.country + ")"
			}
			geo.Unlock()
			return c, nil
		}
		log.Printf("зарубежный выход %q не сработал: %v", r.name, err)
	}
	// зарубежного выхода нет — хотя бы напрямую (вход, скорее всего, не пройдёт)
	return net.DialTimeout("tcp", target, 10*time.Second)
}

func isGeoHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return !hostIn(host, consoleGeoExcept) && hostIn(host, consoleGeo)
}

// Для окна: через что сейчас пойдёт вход в Xbox.
func (a *App) geoView() map[string]any {
	routes := a.geoRoutes()
	geo.Lock()
	d, w, last := geo.direct, geo.warp, geo.lastRoute
	geo.Unlock()
	v := map[string]any{"direct": d, "warp": w, "last": last}
	if len(routes) > 0 {
		r := routes[0]
		s := r.name
		if r.country != "" {
			s += " (" + r.country + ")"
		}
		v["route"], v["ok"] = s, true
	} else {
		v["ok"] = false
	}
	return v
}

// Страны СНГ: VPN-сервер там не помогает обойти российские блокировки.
var cisCountries = map[string]bool{"RU": true, "BY": true, "KZ": true, "KG": true, "AM": true, "AZ": true, "TJ": true, "UZ": true, "MD": true, "TM": true}

func isCIS(cc string) bool { return cisCountries[strings.ToUpper(cc)] }

// Страна по флагу-эмодзи в названии сервера (🇧🇾 → BY).
func flagCountry(name string) string {
	r := []rune(name)
	for i := 0; i+1 < len(r); i++ {
		if r[i] >= 0x1F1E6 && r[i] <= 0x1F1FF && r[i+1] >= 0x1F1E6 && r[i+1] <= 0x1F1FF {
			return string([]rune{'A' + (r[i] - 0x1F1E6), 'A' + (r[i+1] - 0x1F1E6)})
		}
	}
	return ""
}
