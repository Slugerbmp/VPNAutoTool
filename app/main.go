package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	appVersion = "1.12.1"
	uiAddr     = "127.0.0.1:47321"
	proxyAddr  = "127.0.0.1:10820" // сюда смотрит системный прокси Windows
	probeURL   = "https://www.gstatic.com/generate_204"
)

// Локальные входы ядра: HTTP (basePort+i) и SOCKS5 (socksBase+i) на каждый сервер.
// Windows может закрепить диапазон портов за Hyper-V/WSL — тогда ядро не сможет их занять
// и «не принимает соединения». Поэтому диапазоны выбираются из свободных при запуске.
var (
	basePort  = 47400
	socksBase = 47800
)

var portCandidates = [][2]int{{47400, 47800}, {38400, 38800}, {26400, 26800}, {19400, 19800}, {58400, 58800}, {12400, 12800}}

func rangeFree(start, n int, udp bool) bool {
	for p := start; p < start+n; p++ {
		l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			return false
		}
		l.Close()
		if udp {
			u, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				return false
			}
			u.Close()
		}
	}
	return true
}

// Подобрать свободные диапазоны (вызывается, когда ядро не запущено). skip — диапазон, на котором ядро упало.
func pickPorts(n int, skip int) {
	if n < 1 {
		n = 1
	}
	if n > 380 {
		n = 380
	}
	for _, c := range portCandidates {
		if c[0] == skip {
			continue
		}
		if rangeFree(c[0], n, false) && rangeFree(c[1], n, true) {
			if basePort != c[0] {
				log.Printf("порты ядра: %d+ и %d+", c[0], c[1])
			}
			basePort, socksBase = c[0], c[1]
			return
		}
	}
}

//go:embed ui.html
var uiHTML []byte

//go:embed favicon.png
var faviconPNG []byte

var dataDir string

var trayOK bool

var badTagRe = regexp.MustCompile(`outbound config with tag srv-(\d+)`)

type Settings struct {
	Key          string    `json:"key"`
	DirectRu     bool      `json:"directRu"`
	Pinned       string    `json:"pinned"`
	Mode         string    `json:"mode"`
	ZStrategy    string    `json:"zapretStrategy"`
	Warp         bool      `json:"warp"`
	Bypass       []string  `json:"bypass"`
	FirewallOK   bool      `json:"firewallOk"`
	ShareLAN     bool      `json:"shareLan"`
	ShareCons    bool      `json:"shareConsole"`
	Gateway      bool      `json:"gateway"`
	NoAutoUpdate bool      `json:"noAutoUpdate"`
	LastServer   string    `json:"lastServer,omitempty"`
	GwGamesVPN   bool      `json:"gatewayGamesVpn"`
	TgOn         bool      `json:"tgOn"`
	Notify       *bool     `json:"notify,omitempty"`
	Fallback     *bool     `json:"fallback,omitempty"`
	Hotkey       *bool     `json:"hotkey,omitempty"`
	Autostart    bool      `json:"autostart"`
	Theme        string    `json:"theme"`
	AutoBy       string    `json:"autoBy"`
	Profiles     []Profile `json:"profiles"`
	Active       int       `json:"active"`
	LastOn       bool      `json:"lastOn"`
	LegacyCore   bool      `json:"legacyCore"`
	WarpReset    bool      `json:"warpReset"`
	ZExtra       []string  `json:"zapretExtra"`
	Rules        Rules     `json:"rules"`
}

type App struct {
	mu         sync.Mutex
	loadMu     sync.Mutex
	probeMu    sync.Mutex
	probeGen   int               // поколение, для которого заведены probeTr
	probeTr    []*http.Transport // постоянные соединения проверки (по серверу)
	probeFail  []int             // подряд неудачных проверок
	probeRound int
	settings   Settings
	servers    []*Server
	gen        int
	cfg        []byte
	cur        int
	on         bool
	status     string
	errMsg     string
	event      string
	busy       bool
	lastFetch  time.Time
	lastHB     time.Time
	uiSeen     bool
	hist       map[string][]int
	speed      map[string]float64
	speedBusy  bool
	speedDone  int
	speedTotal int
	closingAt  time.Time
}

var app = &App{cur: -1}

func main() {
	dataDir = defaultDataDir()
	os.MkdirAll(filepath.Join(dataDir, "core"), 0755)
	// служебные процессы пишут в свои журналы — иначе они затирали бы журнал программы
	logName := "app.log"
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--zapret-task":
			logName = "zapret-task.log"
		case "--gateway":
			logName = "gateway.log"
		}
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if logName != "app.log" { // журналы служебных процессов дописываем (задача запускается на каждую команду)
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		if st, err := os.Stat(filepath.Join(dataDir, logName)); err == nil && st.Size() > 1<<20 {
			flags |= os.O_TRUNC
		}
	}
	if lf, err := os.OpenFile(filepath.Join(dataDir, logName), flags, 0644); err == nil {
		log.SetOutput(lf)
	}

	if len(os.Args) > 1 && os.Args[1] == "--zapret-task" { // исполнитель с правами администратора
		zapretTaskMain()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--gateway" { // режим шлюза (с правами администратора)
		gatewayMain()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--zapret-setup" {
		// галочка установщика «исключения Защитника» — сначала она, иначе Защитник удалит запрет сразу
		if pd := filepath.Join(dataDir, "pending-defender"); func() bool { _, e := os.Stat(pd); return e == nil }() {
			os.Remove(pd)
			if err := defenderExclude(); err != nil {
				msgBox(err.Error(), 0x30)
			}
		}
		if len(os.Args) > 2 { // архив запрета передан явно
			if data, err := os.ReadFile(os.Args[2]); err == nil {
				if _, err := extractZapretZip(data, zapretDir()); err != nil {
					msgBox("Не удалось распаковать запрет: "+err.Error(), 0x10)
				}
			}
		} else if _, err := os.Stat(filepath.Join(zapretDir(), "bin", "winws.exe")); err != nil {
			// установщик больше не вшивает запрет (антивирусы ругались на WinDivert внутри):
			// скачиваем свежую версию с GitHub автора
			if _, err := zapretDownloadInstall(); err != nil {
				msgBox("Не удалось скачать запрет: "+err.Error()+"\nЕго можно будет установить позже прямо из программы (режим «Запрет»).", 0x30)
				return
			}
		}
		if err := zapretSetupTask(); err != nil {
			msgBox("Не удалось настроить запуск запрета: "+err.Error(), 0x10)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--defender" { // исключения Защитника (запуск с правами администратора)
		if err := defenderExclude(); err != nil {
			msgBox(err.Error(), 0x30)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--autostart" {
		autostartLaunch = true
	}
	if len(os.Args) > 1 && os.Args[1] == "--uninstall" {
		uninstall()
		return
	}

	if selfInstall() { // macOS: перенос в «Программы» при первом запуске
		return
	}

	ln, err := net.Listen("tcp", uiAddr)
	if err != nil && len(os.Args) > 1 && os.Args[1] == "--updated" {
		// после обновления старая копия может ещё завершаться — ждём, пока освободит порт
		for i := 0; i < 40 && err != nil; i++ {
			time.Sleep(500 * time.Millisecond)
			ln, err = net.Listen("tcp", uiAddr)
		}
	}
	if err != nil {
		// уже запущено — показываем окно той копии
		openOrFocusUI()
		return
	}

	killProcess(coreName)
	cleanupStaleProxy()
	if exe, err := os.Executable(); err == nil { // старые копии после обновления поверх запущенной
		if olds, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), "VPNAuto.old-*.exe")); len(olds) > 0 {
			for _, o := range olds {
				os.Remove(o)
			}
		}
	}
	app.loadSettings()
	app.lastHB = time.Now()

	go app.relay()
	go app.prober()
	go app.watchdog()
	go app.refresher()
	go app.zapretMonitor()
	go app.zapretUpdater()
	go app.warpUpdater()
	go app.hotspotInit()
	go app.gatewayLoop()
	go app.updater()
	go defenderRefresh()
	go app.geoLoop() // страны серверов: СНГ — не для автовыбора; вход Xbox — через зарубежные
	go app.tgwsLoop()
	go warpGUIStart() // значок Cloudflare WARP в трее вместе с нашим
	go app.notifier()
	go app.rulesLoop()
	go app.restoreLastOn()
	if app.settings.Key != "" {
		go app.loadServers()
	} else {
		app.setStatus("Вставьте ключ, чтобы начать", "")
	}
	trayOK = startTray()
	if trayOK {
		hotkeySet(app.optHotkey())
	}
	go app.trayUpdater()
	if len(os.Args) > 1 && os.Args[1] == "--updated" {
		app.setEvent("NETtool обновлён до версии " + appVersion)
		go func() {
			time.Sleep(3 * time.Second)
			notify("NETtool", "Обновлено до версии "+appVersion)
		}()
	}
	go func() {
		if autostartLaunch && trayOK {
			return // при автозапуске окно не показываем — программа в трее
		}
		time.Sleep(300 * time.Millisecond)
		openUI()
		// если окно Edge так и не открылось — открываем в обычном браузере
		time.Sleep(15 * time.Second)
		app.mu.Lock()
		seen := app.uiSeen
		app.mu.Unlock()
		if !seen {
			openURL("http://" + uiAddr + "/")
		}
	}()

	apiMux = app.routes()
	http.Serve(ln, apiMux)
}

// ---------- настройки ----------
func (a *App) loadSettings() {
	b, err := os.ReadFile(filepath.Join(dataDir, "settings.json"))
	if err == nil {
		json.Unmarshal(b, &a.settings)
	}
	if a.settings.Bypass == nil {
		a.settings.Bypass = append([]string{}, defaultBypass...)
	}
	bypassList = append([]string{}, a.settings.Bypass...)
	a.migrateProfiles()
	useLegacyCore = a.settings.LegacyCore
	zapretExtra = append([]string{}, a.settings.ZExtra...)
	if !a.settings.WarpReset { // 1.5.3: WARP по умолчанию выключен
		a.settings.Warp, a.settings.WarpReset = false, true
		a.saveSettings()
	}
	// галочка «Запускать вместе с Windows» из установщика
	pa := filepath.Join(dataDir, "pending-autostart")
	if b, err := os.ReadFile(pa); err == nil {
		os.Remove(pa)
		a.settings.Autostart = strings.TrimSpace(string(b)) == "1"
		go setAutostart(a.settings.Autostart)
		a.saveSettings()
	} else if a.settings.Autostart {
		go setAutostart(true) // переименование в NETtool: обновить запись автозапуска
	}
}

func (a *App) saveSettings() {
	b, _ := json.MarshalIndent(a.settings, "", "  ")
	os.WriteFile(filepath.Join(dataDir, "settings.json"), b, 0600)
}

func (a *App) setStatus(status, errMsg string) {
	a.mu.Lock()
	a.status, a.errMsg = status, errMsg
	a.mu.Unlock()
	if errMsg != "" {
		log.Println("ERR:", errMsg)
	}
}

// ---------- загрузка серверов и запуск ядра ----------
func (a *App) loadServers() {
	a.loadMu.Lock()
	defer a.loadMu.Unlock()
	a.mu.Lock()
	key := a.settings.Key
	a.busy = true
	px := a.proxyForCur()
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.busy = false; a.mu.Unlock() }()

	if err := ensureCore(); err != nil {
		a.setStatus("", err.Error())
		return
	}
	a.setStatus("Загружаю серверы…", "")
	servers, body, err := parseInput(key, px)
	a.mu.Lock()
	a.lastFetch = time.Now()
	a.mu.Unlock()
	cache := cachePath(key)
	if err != nil {
		// не скачалась — работаем по последнему сохранённому списку
		if b, e := os.ReadFile(cache); e == nil {
			if cached := parseBody(string(b)); len(cached) > 0 {
				log.Println("подписка не загрузилась, беру кэш:", err)
				a.applyServers(cached)
				a.mu.Lock()
				a.event = time.Now().Format("15:04") + " — подписка не обновилась, работаю по сохранённому списку серверов (повторю позже)"
				a.lastFetch = time.Now().Add(-110 * time.Minute) // повторить через ~10 минут
				a.mu.Unlock()
				return
			}
		}
		a.setStatus("", err.Error())
		return
	}
	os.WriteFile(cache, []byte(body), 0600)
	a.applyServers(servers)
}

func (a *App) applyServers(servers []*Server) {
	// в режиме запрета ядро VPN не запускаем (кроме резерва, где VPN проверяется для возврата)
	if a.mode() == "zapret" && !a.fallbackActive() && !a.consoleWantsCore() {
		stopCore()
		a.mu.Lock()
		a.servers, a.cfg, a.cur = servers, nil, -1
		a.gen++
		a.status = fmt.Sprintf("Серверов: %d. В режиме запрета VPN не запущен", len(servers))
		a.errMsg = ""
		a.mu.Unlock()
		return
	}
	if !coreRunning() {
		pickPorts(len(servers), 0)
	}
	a.mu.Lock()
	cfg := buildConfig(servers, a.settings.DirectRu)
	same := bytes.Equal(cfg, a.cfg) && coreRunning()
	a.mu.Unlock()
	if same {
		a.setStatus("Подписка не изменилась", "")
		return
	}
	a.setStatus("Запускаю ядро…", "")
	// Если Xray отвергает отдельные серверы (например, vless без шифрования) —
	// выкидываем их по одному и пробуем снова, чтобы из-за них не падало всё.
	skipped := []string{}
	for {
		err := startCore(cfg)
		if err == nil && !coreListening() {
			// ядро запустилось, но не заняло свои порты (диапазон закреплён Windows за Hyper-V/WSL
			// или занят другой программой) — берём другой диапазон
			old := basePort
			time.Sleep(1500 * time.Millisecond)
			if !coreListening() {
				log.Println("ядро не открыло порты", old, "— пробую другой диапазон:", lastLines(readCoreLog(), 3))
				stopCore()
				pickPorts(len(servers), old)
				if basePort != old {
					a.mu.Lock()
					cfg = buildConfig(servers, a.settings.DirectRu)
					a.mu.Unlock()
					continue
				}
				err = errors.New("ядро VPN не смогло открыть локальные порты: " + lastLines(readCoreLog(), 2))
			}
		}
		if err == nil {
			break
		}
		if strings.Contains(err.Error(), "without TLS or other encryption is prohibited") && !useLegacyCore {
			// серверы без шифрования: переходим на старое ядро, которое их принимает
			log.Println("в подписке есть vless без шифрования — переключаюсь на ядро Xray", legacyXrayTag)
			useLegacyCore = true
			if e := ensureCore(); e == nil {
				a.mu.Lock()
				a.settings.LegacyCore = true
				a.saveSettings()
				a.mu.Unlock()
				a.setEvent("в подписке есть серверы без шифрования — использую совместимую версию ядра Xray")
				continue
			} else {
				log.Println("старое ядро не скачалось:", e)
				useLegacyCore = false
			}
		}
		m := badTagRe.FindStringSubmatch(err.Error())
		if m == nil || len(servers) <= 1 || len(skipped) >= 50 {
			if strings.Contains(err.Error(), "without TLS") {
				err = errors.New("сервер использует vless без шифрования, а совместимое ядро Xray не скачалось — проверьте интернет и нажмите «Обновить подписку»")
			}
			a.setStatus("", err.Error())
			return
		}
		idx, _ := strconv.Atoi(m[1])
		if idx >= len(servers) {
			a.setStatus("", err.Error())
			return
		}
		log.Printf("пропускаю сервер %q: %v", servers[idx].Name, err)
		skipped = append(skipped, servers[idx].Name)
		servers = append(servers[:idx:idx], servers[idx+1:]...)
		a.mu.Lock()
		cfg = buildConfig(servers, a.settings.DirectRu)
		a.mu.Unlock()
	}
	if len(skipped) > 0 {
		a.mu.Lock()
		a.event = fmt.Sprintf("Пропущено серверов, которые ядро не поддерживает: %d (%s)", len(skipped), strings.Join(skipped, ", "))
		a.mu.Unlock()
	}
	go func() { vpnServerIPs = resolveServerIPs(servers) }()
	a.mu.Lock()
	// сразу подключаемся к серверу, на котором работали в прошлый раз (до закрытия программы
	// или до обновления подписки), — не дожидаясь первой проверки всех серверов
	prev := a.settings.LastServer
	if a.cur >= 0 && a.cur < len(a.servers) {
		prev = a.servers[a.cur].Name
	}
	a.servers = servers
	a.cfg = cfg
	a.gen++
	a.cur = startServer(servers, a.settings.Pinned, prev)
	a.status = fmt.Sprintf("Серверов: %d. Проверяю пинг…", len(servers))
	a.errMsg = ""
	a.mu.Unlock()
	go a.probeAll()
}

// Сервер для старта: закреплённый, иначе прошлый, иначе первый «обычный» (не служебный, не СНГ).
func startServer(servers []*Server, pinned, prev string) int {
	for _, want := range []string{pinned, prev} {
		if want == "" {
			continue
		}
		for i, s := range servers {
			if s.Name == want && (s.Kind == "" || want == pinned) {
				return i
			}
		}
	}
	for i, s := range servers {
		if s.Kind == "" {
			return i
		}
	}
	return 0
}

// Запомнить текущий сервер — с него программа начнёт при следующем запуске (вызывать под a.mu).
func (a *App) rememberCur() {
	if a.cur < 0 || a.cur >= len(a.servers) || a.servers[a.cur].Ping <= 0 {
		return
	}
	if n := a.servers[a.cur].Name; n != a.settings.LastServer {
		a.settings.LastServer = n
		a.saveSettings()
	}
}

func (a *App) refresher() {
	for {
		time.Sleep(time.Minute)
		a.mu.Lock()
		need := a.settings.Key != "" && time.Since(a.lastFetch) > 2*time.Hour
		a.mu.Unlock()
		if need {
			a.loadServers()
		}
	}
}

// Старое ядро Xray (лето 2025) — для серверов vless без шифрования, которые новые версии запрещают.
const legacyXrayTag = "v25.8.3"

var fpRe = regexp.MustCompile(`"fingerprint":\s*"([^"]*)"`)

// Старое ядро не знает новых отпечатков браузера (hellochrome_133 и т.п.) и из-за этого
// выкидывало все REALITY-серверы. Заменяем их на ближайшие поддерживаемые.
func legacyFingerprints(cfg []byte) []byte {
	known := map[string]bool{"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true, "edge": true,
		"360": true, "qq": true, "random": true, "randomized": true, "randomizednoalpn": true, "unsafe": true, "": true}
	return fpRe.ReplaceAllFunc(cfg, func(m []byte) []byte {
		fp := strings.ToLower(string(fpRe.FindSubmatch(m)[1]))
		if known[fp] {
			return m
		}
		repl := "chrome"
		for _, k := range []string{"firefox", "safari", "ios", "edge", "android", "360", "qq", "random", "chrome"} {
			if strings.Contains(fp, k) {
				repl = k
				break
			}
		}
		return []byte(`"fingerprint":"` + repl + `"`)
	})
}

var useLegacyCore bool

func coreDir() string {
	if useLegacyCore {
		return filepath.Join(dataDir, "core-legacy")
	}
	return filepath.Join(dataDir, "core")
}
func coreExe() string { return filepath.Join(coreDir(), coreName) }

func ensureCore() error {
	if _, err := os.Stat(coreExe()); err == nil {
		return nil
	}
	app.setStatus("Скачиваю ядро Xray (один раз, ~15 МБ)…", "")
	os.MkdirAll(coreDir(), 0755)
	u := xrayURL()
	if useLegacyCore {
		u = strings.Replace(u, "latest/download", "download/"+legacyXrayTag, 1)
	}
	cl := &http.Client{Timeout: 5 * time.Minute}
	resp, err := cl.Get(u)
	if err != nil {
		return fmt.Errorf("не удалось скачать ядро Xray с GitHub: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("не удалось скачать ядро Xray: GitHub ответил %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("обрыв при скачивании ядра: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return errors.New("скачанный архив ядра повреждён")
	}
	found := false
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		dst := ""
		switch {
		case strings.EqualFold(base, "xray.exe") || base == "xray":
			dst = coreName + ".tmp"
			found = true
		case strings.HasSuffix(base, ".dat"):
			dst = base
		default:
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(coreDir(), dst), data, 0755); err != nil {
			return err
		}
	}
	if !found {
		return errors.New("в архиве нет программы xray")
	}
	return os.Rename(filepath.Join(coreDir(), coreName+".tmp"), coreExe())
}

var (
	coreMu  sync.Mutex
	coreCmd *exec.Cmd
)

func coreRunning() bool {
	coreMu.Lock()
	defer coreMu.Unlock()
	return coreCmd != nil
}

func stopCore() {
	coreMu.Lock()
	c := coreCmd
	coreCmd = nil
	coreMu.Unlock()
	if c != nil && c.Process != nil {
		c.Process.Kill()
	}
}

func startCore(cfg []byte) error {
	stopCore()
	if useLegacyCore {
		cfg = legacyFingerprints(cfg)
	}
	path := filepath.Join(coreDir(), "config.json")
	if err := os.WriteFile(path, cfg, 0600); err != nil {
		return err
	}
	test := hiddenCmd(coreExe(), "run", "-test", "-c", path)
	test.Dir = coreDir()
	if out, err := test.CombinedOutput(); err != nil {
		return fmt.Errorf("ядро Xray не приняло настройки: %s", errorLines(string(out)))
	}
	cmd := hiddenCmd(coreExe(), "run", "-c", path)
	cmd.Dir = coreDir()
	lf, _ := os.Create(filepath.Join(dataDir, "core.log"))
	if lf != nil {
		cmd.Stdout, cmd.Stderr = lf, lf
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("не удалось запустить ядро: %v", err)
	}
	coreMu.Lock()
	coreCmd = cmd
	coreMu.Unlock()
	go func() {
		cmd.Wait()
		if lf != nil {
			lf.Close()
		}
		coreMu.Lock()
		crashed := coreCmd == cmd
		if crashed {
			coreCmd = nil
		}
		coreMu.Unlock()
		if crashed {
			now := time.Now()
			coreMu.Lock()
			recent := coreCrashes[:0]
			for _, t := range coreCrashes {
				if now.Sub(t) < time.Minute {
					recent = append(recent, t)
				}
			}
			coreCrashes = append(recent, now)
			n := len(coreCrashes)
			coreMu.Unlock()
			if _, err := os.Stat(coreExe()); err != nil {
				msg := "Файл ядра VPN исчез — скорее всего, его удалил антивирус. Добавьте папку " + coreDir() + " в исключения антивируса и нажмите «Обновить подписку»"
				log.Println(msg)
				if app != nil {
					app.setStatus("", msg)
				}
				return
			}
			if n >= 3 {
				msg := "Ядро VPN постоянно падает: " + lastLines(readCoreLog(), 2) + ". Возможно, его блокирует антивирус"
				log.Println(msg)
				if app != nil {
					app.setStatus("", msg)
				}
				return
			}
			log.Println("ядро завершилось само, перезапуск")
			time.Sleep(3 * time.Second)
			if !coreRunning() {
				startCore(cfg)
			}
		}
	}()
	time.Sleep(700 * time.Millisecond)
	return nil
}

// Слушает ли ядро свой первый вход.
func coreListening() bool {
	if !coreRunning() {
		return false
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort), 700*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func readCoreLog() string {
	b, _ := os.ReadFile(filepath.Join(dataDir, "core.log"))
	return string(b)
}

var coreCrashes []time.Time

func errorLines(s string) string {
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if !strings.Contains(l, "[Warning]") && strings.TrimSpace(l) != "" {
			keep = append(keep, strings.TrimSpace(l))
		}
	}
	if len(keep) == 0 {
		return lastLines(s, 3)
	}
	return strings.Join(keep, " | ")
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// ---------- пинг и выбор сервера ----------
func (a *App) prober() {
	for {
		time.Sleep(10 * time.Second)
		a.probeAll()
	}
}

func newProbeTransport(i int) *http.Transport {
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", basePort+i))
	return &http.Transport{Proxy: http.ProxyURL(pu), TLSHandshakeTimeout: 6 * time.Second,
		MaxIdleConnsPerHost: 1, IdleConnTimeout: 45 * time.Second}
}

func probe(i int) (int, string) {
	tr := newProbeTransport(i)
	defer tr.CloseIdleConnections()
	return probeWith(tr, false)
}

// warm=true — соединение уже прогрето прошлой проверкой: хватает одного замера.
func probeWith(tr *http.Transport, warm bool) (int, string) {
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	hit := func() error {
		resp, err := cl.Get(probeURL)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 204 && resp.StatusCode != 200 {
			return fmt.Errorf("ответ %d", resp.StatusCode)
		}
		return nil
	}
	if warm {
		t := time.Now()
		if hit() == nil {
			return max(int(time.Since(t).Milliseconds()), 1), ""
		}
		tr.CloseIdleConnections() // соединение протухло — проверяем заново
	}
	if err := hit(); err != nil { // первый запрос прогревает соединение
		return -1, probeReason(err)
	}
	t := time.Now()
	if err := hit(); err != nil { // второй — это и есть пинг через VPN
		return -1, probeReason(err)
	}
	ms := int(time.Since(t).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, ""
}

// Понятное объяснение ошибки проверки.
func probeReason(err error) string {
	e := strings.ToLower(err.Error())
	switch {
	case strings.Contains(e, "timeout") || strings.Contains(e, "deadline"):
		return "сервер не ответил вовремя (таймаут)"
	case strings.Contains(e, "eof") || strings.Contains(e, "reset"):
		return "соединение оборвано (сервер или провайдер разрывает подключение)"
	case strings.Contains(e, "refused"):
		return "ядро не принимает соединения"
	case strings.Contains(e, "certificate") || strings.Contains(e, "tls"):
		return "ошибка шифрования: " + err.Error()
	}
	return err.Error()
}

func (a *App) probeAll() {
	a.probeMu.Lock()
	defer a.probeMu.Unlock()
	if !coreRunning() {
		return
	}
	a.mu.Lock()
	n, gen := len(a.servers), a.gen
	res := make([]int, n)
	errs := make([]string, n)
	for i := 0; i < n; i++ {
		res[i], errs[i] = a.servers[i].Ping, a.servers[i].Err
	}
	a.mu.Unlock()
	if a.probeGen != gen || len(a.probeTr) != n {
		for _, t := range a.probeTr {
			t.CloseIdleConnections()
		}
		a.probeTr, a.probeFail, a.probeGen = make([]*http.Transport, n), make([]int, n), gen
		for i := range a.probeTr {
			a.probeTr[i] = newProbeTransport(i)
		}
	}
	a.probeRound++
	var wg sync.WaitGroup
	sem := make(chan struct{}, 12)
	for i := 0; i < n; i++ {
		// давно молчащие серверы проверяем реже (каждый 6-й круг), чтобы не тратить время и трафик
		if a.probeFail[i] >= 3 && a.probeRound%6 != 0 {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			res[i], errs[i] = probeWith(a.probeTr[i], a.probeFail[i] == 0 && res[i] > 0)
			if res[i] > 0 {
				a.probeFail[i] = 0
			} else {
				a.probeFail[i]++
			}
			<-sem
		}(i)
	}
	wg.Wait()
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen != a.gen {
		return
	}
	for i, p := range res {
		a.servers[i].Ping = p
		a.servers[i].Err = errs[i]
	}
	a.choose()
	a.rememberCur()
	alive := 0
	for _, s := range a.servers {
		if s.Ping > 0 {
			alive++
		}
	}
	if a.errMsg == "" {
		a.status = fmt.Sprintf("Серверов: %d, отвечают: %d", n, alive)
	}
	a.recordHistory()
	go a.checkFallback(alive, n)
}

// вызывать под a.mu
func (a *App) choose() {
	if len(a.servers) == 0 {
		a.cur = -1
		return
	}
	pin := -1
	if a.settings.Pinned != "" {
		for i, s := range a.servers {
			if s.Name == a.settings.Pinned {
				pin = i
				break
			}
		}
	}
	if pin >= 0 && a.servers[pin].Ping > 0 {
		a.cur = pin
		return
	}
	// автовыбор: только серверы «для интернета», по надёжности и среднему пингу
	best := -1
	for i, s := range a.servers {
		if s.Ping > 0 && s.Kind == "" && (best < 0 || a.score(s) < a.score(a.servers[best])) {
			best = i
		}
	}
	if best < 0 {
		return // все молчат — оставляем как есть
	}
	// текущий — торрентный/служебный (не выбран вручную) → сразу на нормальный
	if a.cur >= 0 && a.cur < len(a.servers) && a.servers[a.cur].Kind != "" {
		a.cur = best
		return
	}
	if a.settings.AutoBy == "speed" && len(a.speed) > 0 {
		sb := -1
		for i, s := range a.servers {
			if s.Ping > 0 && a.speed[s.Name] > 0 && (sb < 0 || a.speed[s.Name] > a.speed[a.servers[sb].Name]) {
				sb = i
			}
		}
		if sb >= 0 {
			curOK := a.cur >= 0 && a.cur < len(a.servers) && a.servers[a.cur].Ping > 0
			if !curOK || (a.cur != sb && a.speed[a.servers[sb].Name] > a.speed[a.servers[a.cur].Name]*1.3) {
				if curOK || a.cur >= 0 {
					a.event = fmt.Sprintf("%s — переключено на самый скоростной «%s»", time.Now().Format("15:04"), a.servers[sb].Name)
				}
				a.cur = sb
			}
			return
		}
	}
	if a.cur < 0 || a.cur >= len(a.servers) || a.servers[a.cur].Ping <= 0 {
		if a.cur >= 0 && a.cur < len(a.servers) && a.cur != best {
			a.event = fmt.Sprintf("%s — «%s» не отвечал, переключено на «%s»",
				time.Now().Format("15:04"), a.servers[a.cur].Name, a.servers[best].Name)
		}
		a.cur = best
		return
	}
	c, b := a.score(a.servers[a.cur]), a.score(a.servers[best])
	if b < c-40 && b < c*0.7 { // заметно надёжнее/быстрее — переключаемся
		a.event = fmt.Sprintf("%s — переключено на более стабильный «%s»", time.Now().Format("15:04"), a.servers[best].Name)
		a.cur = best
	}
}

func (a *App) proxyForCur() string { // под a.mu
	if a.cur >= 0 && a.cur < len(a.servers) && coreRunning() {
		return fmt.Sprintf("http://127.0.0.1:%d", basePort+a.cur)
	}
	return ""
}

// ---------- локальный прокси: перекидывает соединения в выбранный сервер ----------
func (a *App) relay() {
	ln, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		a.setStatus("", "порт "+proxyAddr+" занят другой программой (может, открыт Happ?)")
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			a.mu.Lock()
			idx := a.cur
			a.mu.Unlock()
			if idx < 0 {
				return
			}
			up, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+idx), 3*time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(up, c); done <- struct{}{} }()
			go func() { io.Copy(c, up); done <- struct{}{} }()
			<-done
		}(c)
	}
}

// ---------- закрытие окна = выход ----------
func (a *App) watchdog() {
	for {
		time.Sleep(2 * time.Second)
		if trayOK {
			continue
		}
		a.mu.Lock()
		hb, cl := a.lastHB, a.closingAt
		a.mu.Unlock()
		if (!cl.IsZero() && time.Since(cl) > 5*time.Second && hb.Before(cl)) || time.Since(hb) > 3*time.Minute {
			shutdown()
		}
	}
}

var shuttingDown sync.Once

// Полный выход: выключить всё, закрыть окна программы, убрать значок и завершить процесс.
func shutdown() {
	shuttingDown.Do(doShutdown)
	select {} // второй вызов просто ждёт завершения первого
}

func doShutdown() {
	// страховка: что бы ни зависло — через 15 секунд процесс завершится
	go func() { time.Sleep(15 * time.Second); trayRemove(); os.Exit(0) }()
	app.mu.Lock()
	on := app.on
	app.mu.Unlock()
	if on {
		setSysProxy(false)
	}
	if zapretSupported && winwsRunning() {
		app.zapretOff()
	}
	hotspotShutdown()
	gwMgr.Lock()
	gwRun, gwIdx := gwMgr.running, gwMgr.ifIdx
	gwMgr.Unlock()
	if gwRun {
		writeGWConfig(gwConfig{On: false, TS: time.Now().Unix()})
		zapretRun(zCmd{Action: "gateway-off", IfIdx: gwIdx}, 10*time.Second)
	}
	if tgwsSupported && tgwsRunning() {
		tgwsStop()
	}
	stopCore()
	killProcess(coreName) // на случай, если ядро успело перезапуститься
	closeUIWindows()
	trayRemove()
	os.Exit(0)
}

func (a *App) powerState() (on, ready bool) {
	if a.mode() == "zapret" {
		return a.anyOn(), !a.zapretBusy()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.on, coreRunning() && a.cur >= 0
}

func (a *App) powerOn() error {
	if _, ready := a.powerState(); !ready {
		return errors.New("Серверы ещё не готовы")
	}
	if err := setSysProxy(true); err != nil {
		return err
	}
	a.mu.Lock()
	a.on = true
	a.mu.Unlock()
	if tgwsSupported && tgwsRunning() { // TG WS Proxy не работает вместе с VPN
		tgwsStop()
	}
	return nil
}

// Запустить ядро VPN, если оно остановлено (например, после режима запрета).
func (a *App) ensureCore() {
	if coreRunning() {
		return
	}
	a.mu.Lock()
	servers := a.servers
	a.mu.Unlock()
	if len(servers) == 0 {
		a.loadServers()
		return
	}
	a.loadMu.Lock()
	a.mu.Lock()
	a.cfg = nil
	a.mu.Unlock()
	a.applyServers(servers)
	a.loadMu.Unlock()
}

// подсказка и цвет значка в трее
func (a *App) trayUpdater() {
	for {
		a.mu.Lock()
		tip := "NETtool — выключен"
		if a.on {
			tip = "NETtool — VPN включён"
		}
		if a.cur >= 0 && a.cur < len(a.servers) {
			s := a.servers[a.cur]
			tip += "\n" + s.Name
			if s.Ping > 0 {
				tip += fmt.Sprintf(" · %d мс", s.Ping)
			}
		} else if a.errMsg != "" {
			tip += "\nОшибка — откройте окно"
		}
		on := a.on
		a.mu.Unlock()
		zi.mu.Lock()
		if zi.running {
			on = true
			tip = "NETtool — запрет включён"
			if zi.warpOn {
				tip += " + WARP"
			}
		}
		zi.mu.Unlock()
		traySet(on, tip)
		time.Sleep(2 * time.Second)
	}
}

// ---------- HTTP API для окна ----------
type srvView struct {
	Name string `json:"name"`
	Ping int    `json:"ping"`
	Err  string `json:"err,omitempty"`
	Kind string `json:"kind,omitempty"`
	Stab int    `json:"stab"`
}

func (a *App) routes() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(uiHTML)
	})
	m.HandleFunc("/favicon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(faviconPNG)
	})
	m.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		if r.URL.Query().Get("src") != "tray" {
			a.lastHB = time.Now()
			a.uiSeen = true
		}
		list := make([]srvView, len(a.servers))
		for i, s := range a.servers {
			list[i] = srvView{s.Name, s.Ping, s.Err, s.Kind, a.stability(s.Name)}
		}
		resp := map[string]any{
			"version": appVersion, "configured": a.settings.Key != "", "keyHint": keyHint(a.settings.Key),
			"on": a.on, "cur": a.cur, "pinned": a.settings.Pinned, "servers": list,
			"status": a.status, "error": a.errMsg, "event": a.event, "directRu": a.settings.DirectRu,
			"busy": a.busy, "core": coreRunning(), "tray": trayOK,
			"mode": a.modeLocked(), "bypass": a.settings.Bypass, "zextra": a.settings.ZExtra,
		}
		a.mu.Unlock()
		resp["zapret"] = a.zapretView()
		resp["hotspot"] = a.hotspotView()
		resp["tgws"] = a.tgwsView()
		a.mu.Lock()
		for k, v := range a.featureView() {
			resp[k] = v
		}
		a.mu.Unlock()
		writeJSON(w, resp)
	})
	m.HandleFunc("/api/key", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Key string }
		json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		a.settings.Key = strings.TrimSpace(req.Key)
		a.settings.Pinned = ""
		os.Remove(cachePath(a.settings.Key))
		if len(a.settings.Profiles) == 0 && a.settings.Key != "" {
			a.settings.Profiles = []Profile{{Name: "Основная"}}
			a.settings.Active = 0
		}
		if a.settings.Active < len(a.settings.Profiles) {
			if a.settings.Key == "" {
				a.settings.Profiles = append(a.settings.Profiles[:a.settings.Active:a.settings.Active], a.settings.Profiles[a.settings.Active+1:]...)
				a.settings.Active = 0
				if len(a.settings.Profiles) > 0 {
					a.settings.Key = a.settings.Profiles[0].Key
				}
			} else {
				a.settings.Profiles[a.settings.Active].Key = a.settings.Key
			}
		}
		a.saveSettings()
		a.mu.Unlock()
		if a.settings.Key == "" {
			a.powerOff()
			stopCore()
			a.mu.Lock()
			a.servers, a.cfg, a.cur = nil, nil, -1
			a.gen++
			a.mu.Unlock()
			a.setStatus("Вставьте ключ, чтобы начать", "")
		} else {
			go a.loadServers()
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/power", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ On bool }
		json.NewDecoder(r.Body).Decode(&req)
		if !req.On {
			a.allOff()
			writeJSON(w, map[string]any{"ok": true})
			return
		}
		if err := a.modeOn(); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/select", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name string }
		json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		a.settings.Pinned = req.Name
		a.saveSettings()
		for i, s := range a.servers {
			if s.Name == req.Name {
				a.cur = i
			}
		}
		if req.Name == "" {
			a.choose()
		}
		a.rememberCur()
		a.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/directru", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Value bool }
		json.NewDecoder(r.Body).Decode(&req)
		a.mu.Lock()
		a.settings.DirectRu = req.Value
		a.saveSettings()
		servers := a.servers
		a.mu.Unlock()
		if len(servers) > 0 {
			go func() { a.loadMu.Lock(); defer a.loadMu.Unlock(); a.applyServers(servers) }()
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/refresh", func(w http.ResponseWriter, r *http.Request) {
		go a.loadServers()
		writeJSON(w, map[string]any{"ok": true})
	})
	// команды из значка в трее / строке меню и кнопки «Выход» в окне
	m.HandleFunc("/api/tray", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("do") {
		case "open":
			go openOrFocusUI()
		case "toggle":
			if a.anyOn() {
				a.allOff()
			} else if err := a.modeOn(); err != nil {
				writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
				return
			}
		case "quit":
			go func() { time.Sleep(300 * time.Millisecond); shutdown() }()
		default:
			// остальные команды меню — через те же обработчики, что и окно
			q := r.URL.Query()
			var path string
			var body any
			switch q.Get("do") {
			case "select":
				path, body = "/api/select", map[string]any{"name": q.Get("name")}
			case "refresh":
				path, body = "/api/refresh", map[string]any{}
			case "mode":
				path, body = "/api/mode", map[string]any{"mode": q.Get("mode")}
			case "warp":
				path, body = "/api/warp", map[string]any{"on": q.Get("on") == "1"}
			case "hotspot":
				path, body = "/api/hotspot", map[string]any{"on": q.Get("on") == "1"}
			case "strategy":
				path, body = "/api/zapret/strategy", map[string]any{"file": q.Get("file")}
			case "test":
				path, body = "/api/zapret/test", map[string]any{}
			case "zupdate":
				path, body = "/api/zapret/update", map[string]any{}
			case "tgws":
				path, body = "/api/tgws", map[string]any{"on": q.Get("on") == "1"}
			case "directru":
				path, body = "/api/directru", map[string]any{"value": q.Get("on") == "1"}
			}
			if path != "" {
				res := callAPI(path, body)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Write(res)
				return
			}
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	a.modeRoutes(m)
	a.extraRoutes(m)
	a.featureRoutes(m)
	frameRoutes(m)
	a.updateRoutes(m)
	m.HandleFunc("/api/closing", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.closingAt = time.Now()
		a.mu.Unlock()
	})
	return m
}

func (a *App) powerOff() {
	a.mu.Lock()
	was := a.on
	a.on = false
	tg := a.settings.TgOn
	a.mu.Unlock()
	if was {
		setSysProxy(false)
		if tg && tgwsSupported && tgwsInstalled() { // вернуть TG WS Proxy, раз VPN выключен
			go tgwsStart()
		}
	}
}

func keyHint(k string) string {
	if k == "" {
		return ""
	}
	if u, err := url.Parse(k); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		return u.Scheme + "://" + u.Host + "/•••••"
	}
	r := []rune(k)
	if len(r) > 14 {
		return string(r[:14]) + "•••••"
	}
	return "•••••"
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

// ---------- окно ----------
func openUI() { openUIURL("http://"+uiAddr+"/", "440,780") }

func openUIURL(u, size string) {
	for _, p := range browserPaths() {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command(p, "--app="+u, "--window-size="+size,
				"--user-data-dir="+filepath.Join(dataDir, "ui"),
				"--no-first-run", "--no-default-browser-check",
				"--disable-background-timer-throttling", "--disable-renderer-backgrounding",
				"--disable-backgrounding-occluded-windows", "--disable-features=msEdgeStartupBoost")
			detach(cmd)
			if cmd.Start() == nil {
				afterOpenUI()
				return
			}
		}
	}
	openURL(u)
}

func (a *App) modeLocked() string { // под a.mu
	if a.settings.Mode == "zapret" && zapretSupported {
		return "zapret"
	}
	return "vpn"
}

var apiMux *http.ServeMux

// Вызов обработчика API изнутри программы (для меню в трее).
func callAPI(path string, body any) []byte {
	if apiMux == nil {
		return nil
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	rec := httptest.NewRecorder()
	apiMux.ServeHTTP(rec, req)
	return rec.Body.Bytes()
}

// Снимок состояния для меню в трее.
type trayMenuState struct {
	Mode, ZStrategy, Pinned                                 string
	On, Ready, VPNOn, ZRunning, ZBusy, ZSupported           bool
	WarpOn, WarpWant, WarpInst, HsOn, HsSupported, DirectRu bool
	TgSupported, TgOn                                       bool
	Cur                                                     int
	Servers                                                 []srvView
	Strategies                                              []string
}

func (a *App) trayState() trayMenuState {
	var s trayMenuState
	s.On, s.Ready = a.powerState()
	s.Mode = a.mode()
	a.mu.Lock()
	s.VPNOn, s.Cur, s.Pinned, s.ZStrategy, s.WarpWant, s.DirectRu = a.on, a.cur, a.settings.Pinned, a.settings.ZStrategy, a.settings.Warp, a.settings.DirectRu
	for _, sv := range a.servers {
		s.Servers = append(s.Servers, srvView{sv.Name, sv.Ping, sv.Err, sv.Kind, 0})
	}
	a.mu.Unlock()
	zi.mu.Lock()
	s.ZRunning, s.ZBusy, s.WarpOn, s.WarpInst, s.HsOn = zi.running, zi.busy, zi.warpOn, zi.warpInst, zi.hsOn
	zi.mu.Unlock()
	s.ZSupported, s.HsSupported, s.TgSupported = zapretSupported, hotspotSupported, tgwsSupported
	zi.mu.Lock()
	s.TgOn = zi.tgRunning
	zi.mu.Unlock()
	if zapretSupported {
		s.Strategies = listStrategies(zapretDir())
	}
	return s
}

// Доля успешных проверок за последние ~5 минут (0–100), -1 — данных мало.
func (a *App) stability(name string) int { // под a.mu
	h := a.hist[name]
	if len(h) > 30 {
		h = h[len(h)-30:]
	}
	if len(h) < 3 {
		return -1
	}
	ok := 0
	for _, v := range h {
		if v > 0 {
			ok++
		}
	}
	return ok * 100 / len(h)
}

// Оценка сервера: меньше — лучше. Медиана пинга + штраф за обрывы.
func (a *App) score(s *Server) float64 { // под a.mu
	h := a.hist[s.Name]
	var pos []int
	for i := len(h) - 1; i >= 0 && len(pos) < 10; i-- {
		if h[i] > 0 {
			pos = append(pos, h[i])
		}
	}
	if s.Ping > 0 {
		pos = append(pos, s.Ping)
	}
	if len(pos) == 0 {
		return 1e9
	}
	sort.Ints(pos)
	med := float64(pos[len(pos)/2])
	rate := 1.0
	if st := a.stability(s.Name); st >= 0 {
		rate = float64(st) / 100
	}
	return med*(1+(1-rate)*3) + (1-rate)*600
}
