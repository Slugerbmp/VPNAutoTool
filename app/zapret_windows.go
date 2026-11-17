//go:build windows

package main

// Zapret на Windows.
// winws.exe нужны права администратора. Чтобы не спрашивать UAC при каждом включении,
// один раз (при установке) создаётся задача планировщика «VPNAuto\Zapret» с наивысшими правами.
// Программа пишет команду в zapret-cmd.json и запускает задачу; задача (VPNAuto.exe --zapret-task)
// выполняет команду и пишет результат в zapret-state.json.

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
)

const zapretSupported = true
const zapretTaskName = `VPNAuto\Zapret`

type zCmd struct {
	Req      int64    `json:"req"`
	Action   string   `json:"action"` // start | stop | test | update
	Strategy string   `json:"strategy"`
	Warp     bool     `json:"warp"`
	Bypass   []string `json:"bypass"`
	VPNIPs   []string `json:"vpnIps"`
	IfIdx    int      `json:"ifIdx,omitempty"`
	Extra    []string `json:"extra"`
}

type zState struct {
	Req     int64     `json:"req"`
	Busy    bool      `json:"busy"`
	Phase   string    `json:"phase"`
	Done    int       `json:"done"`
	Total   int       `json:"total"`
	Current string    `json:"current"`
	Results []zResult `json:"results"`
	Best    string    `json:"best"`
	Error   string    `json:"error"`
	Version string    `json:"version"`
	Time    int64     `json:"time"`
}

func zapretDir() string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "zapret")
}
func zCmdPath() string   { return filepath.Join(dataDir, "zapret-cmd.json") }
func zStatePath() string { return filepath.Join(dataDir, "zapret-state.json") }

func zapretInstalled() bool {
	_, err := os.Stat(filepath.Join(zapretDir(), "bin", "winws.exe"))
	return err == nil
}

func winwsRunning() bool {
	return processRunning("winws.exe")
}

func readZState() zState {
	var s zState
	if b, err := os.ReadFile(zStatePath()); err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}

func writeJSONFile(p string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	tmp := p + ".tmp"
	os.WriteFile(tmp, b, 0644)
	os.Rename(tmp, p)
}

// ---------- задача планировщика ----------
func zapretTaskExists() bool {
	return hiddenCmd("schtasks", "/query", "/tn", zapretTaskName).Run() == nil
}

func xmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// Вызывается с правами администратора: VPNAuto.exe --zapret-setup
func zapretSetupTask() error {
	exe, _ := os.Executable()
	user := os.Getenv("USERDOMAIN") + `\` + os.Getenv("USERNAME")
	x := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>NETtool: включение и выключение Zapret без запроса UAC</Description></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>` + xmlEsc(user) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + xmlEsc(exe) + `</Command><Arguments>--zapret-task</Arguments></Exec></Actions>
</Task>`
	u := utf16.Encode([]rune(x))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	f := filepath.Join(os.TempDir(), "vpnauto-task.xml")
	if err := os.WriteFile(f, b, 0644); err != nil {
		return err
	}
	defer os.Remove(f)
	out, err := hiddenCmd("schtasks", "/create", "/tn", zapretTaskName, "/xml", f, "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Из обычной программы: один раз спросить UAC и создать задачу.
func zapretEnsureTask() error {
	if zapretTaskExists() {
		return nil
	}
	exe, _ := os.Executable()
	ps := fmt.Sprintf(`Start-Process -FilePath '%s' -ArgumentList '--zapret-setup' -Verb RunAs -Wait`, strings.ReplaceAll(exe, "'", "''"))
	if err := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run(); err != nil {
		return errors.New("нужно разрешить запуск с правами администратора (один раз)")
	}
	if !zapretTaskExists() {
		return errors.New("не удалось создать задачу для запуска Zapret")
	}
	return nil
}

var zReqMu sync.Mutex

// Отправить команду исполнителю. wait — ждать завершения.
func zapretRun(c zCmd, wait time.Duration) (zState, error) {
	zReqMu.Lock()
	defer zReqMu.Unlock()
	if err := zapretEnsureTask(); err != nil {
		return zState{}, err
	}
	c.Req = time.Now().UnixNano()
	c.Bypass = bypassList
	c.VPNIPs = vpnServerIPs
	c.Extra = zapretExtra
	writeJSONFile(zCmdPath(), c)
	if out, err := hiddenCmd("schtasks", "/run", "/tn", zapretTaskName).CombinedOutput(); err != nil {
		return zState{}, fmt.Errorf("не удалось запустить задачу: %s", strings.TrimSpace(string(out)))
	}
	if wait == 0 {
		return zState{}, nil
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(400 * time.Millisecond)
		s := readZState()
		if s.Req == c.Req && !s.Busy {
			if s.Error != "" {
				return s, errors.New(s.Error)
			}
			return s, nil
		}
	}
	return readZState(), errors.New("Zapret не ответил вовремя")
}

// ---------- исполнитель (с правами администратора) ----------
func zapretTaskMain() {
	if lf, err := os.OpenFile(filepath.Join(dataDir, "zapret.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		log.SetOutput(lf)
	}
	var c zCmd
	b, err := os.ReadFile(zCmdPath())
	if err != nil || json.Unmarshal(b, &c) != nil {
		return
	}
	if c.Bypass != nil {
		bypassList = c.Bypass
	}
	vpnServerIPs = c.VPNIPs
	zapretExtra = c.Extra
	st := readZState()
	st.Req, st.Busy, st.Error, st.Phase = c.Req, true, "", c.Action
	st.Done, st.Total = 0, 0
	writeJSONFile(zStatePath(), st)
	log.Printf("команда %s %q warp=%v", c.Action, c.Strategy, c.Warp)

	var runErr error
	switch c.Action {
	case "stop":
		killWinws()
	case "start":
		runErr = startWinws(c.Strategy, c.Warp)
	case "test":
		runErr = zapretAutoTest(&st, c.Warp)
	case "warp-install":
		runErr = warpInstall(&st)
	case "gateway":
		runErr = gatewayStartElevated(c.IfIdx)
	case "gateway-off":
		gatewayStopElevated(c.IfIdx)
	case "firewall":
		exe, _ := os.Executable()
		hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=VPN Auto hotspot").Run()
		if out, err := hiddenCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=VPN Auto hotspot", "dir=in", "action=allow",
			"program="+exe, "enable=yes", "profile=any").CombinedOutput(); err != nil {
			runErr = fmt.Errorf("брандмауэр: %s", strings.TrimSpace(string(out)))
		}
		// порты для приставок (DNS, HTTP, HTTPS) и прокси раздачи — отдельными правилами
		hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=VPN Auto consoles").Run()
		for _, pr := range []string{"tcp", "udp"} {
			ports := "53,80,443,10830"
			if pr == "udp" {
				ports = "53"
			}
			hiddenCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=VPN Auto consoles", "dir=in", "action=allow",
				"protocol="+pr, "localport="+ports, "enable=yes", "profile=any").Run()
		}
		// Windows сама создаёт запрещающие правила, если окно «Разрешить доступ» когда-то закрыли —
		// они сильнее разрешающих. Убираем их для нашей программы.
		ps := `$p=` + psQuote(exe) + `; Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object { $_.Program -eq $p } | ` +
			`Get-NetFirewallRule | Where-Object { $_.Action -eq 'Block' -and $_.Direction -eq 'Inbound' } | Remove-NetFirewallRule`
		hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
	case "update":
		was := winwsRunning()
		killWinws()
		var v string
		v, runErr = zapretDownloadInstall()
		st.Version = v
		if was && c.Strategy != "" {
			if _, err := os.Stat(filepath.Join(zapretDir(), c.Strategy)); err == nil {
				startWinws(c.Strategy, c.Warp)
			}
		}
	}
	st.Busy = false
	st.Time = time.Now().Unix()
	if runErr != nil {
		st.Error = runErr.Error()
		log.Println("ошибка:", runErr)
	}
	if st.Version == "" {
		st.Version = zapretVersionOf(zapretDir())
	}
	writeJSONFile(zStatePath(), st)
}

func killWinws() {
	hiddenCmd("taskkill", "/F", "/IM", "winws.exe").Run()
	for i := 0; i < 20 && winwsRunning(); i++ {
		time.Sleep(150 * time.Millisecond)
	}
}

func startWinws(strategy string, warp bool) error {
	zdir := zapretDir()
	writeZapretLists(zdir)
	line, err := buildCmdline(zdir, strategy, warp)
	if err != nil {
		return err
	}
	killWinws()
	exe := filepath.Join(zdir, "bin", "winws.exe")
	try := func(flags uint32) error {
		cmd := exec.Command(exe)
		cmd.Dir = filepath.Join(zdir, "bin")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: flags, CmdLine: line}
		return cmd.Start()
	}
	// пытаемся «выйти» из job-объекта задачи, чтобы winws жил после её завершения
	if err := try(0x08000000 | 0x01000000); err != nil {
		if err := try(0x08000000); err != nil {
			return fmt.Errorf("не удалось запустить winws.exe: %v", err)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	if !winwsRunning() {
		return errors.New("winws.exe сразу завершился — возможно, его удалил антивирус (добавьте папку zapret в исключения)")
	}
	return nil
}

func probeDirect(target string) (bool, int) {
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{}, TLSHandshakeTimeout: 5 * time.Second, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t := time.Now()
	resp, err := cl.Get(target)
	if err != nil {
		return false, 0
	}
	io.CopyN(io.Discard, resp.Body, 16<<10)
	resp.Body.Close()
	return true, int(time.Since(t).Milliseconds())
}

func zapretAutoTest(st *zState, warp bool) error {
	strategies := listStrategies(zapretDir())
	if len(strategies) == 0 {
		return errors.New("не найдено ни одной стратегии")
	}
	st.Results, st.Total, st.Done, st.Best = nil, len(strategies), 0, ""
	for _, s := range strategies {
		st.Current = strategyTitle(s)
		writeJSONFile(zStatePath(), st)
		r := zResult{Name: s, Of: len(zapretTargets)}
		if err := startWinws(s, warp); err == nil {
			time.Sleep(1 * time.Second)
			var wg sync.WaitGroup
			var mu sync.Mutex
			for _, t := range zapretTargets {
				wg.Add(1)
				go func(t string) {
					defer wg.Done()
					ok, ms := probeDirect(t)
					mu.Lock()
					if ok {
						r.OK++
						r.Ms += ms
					}
					mu.Unlock()
				}(t)
			}
			wg.Wait()
			if r.OK > 0 {
				r.Ms /= r.OK
			}
		}
		log.Printf("тест %s: %d/%d, %d мс", s, r.OK, r.Of, r.Ms)
		st.Results = append(st.Results, r)
		st.Done++
		writeJSONFile(zStatePath(), st)
	}
	best := -1
	for i, r := range st.Results {
		if r.OK == 0 {
			continue
		}
		if best < 0 || r.OK > st.Results[best].OK || (r.OK == st.Results[best].OK && r.Ms < st.Results[best].Ms) {
			best = i
		}
	}
	if best < 0 {
		killWinws()
		return errors.New("ни одна стратегия не открыла проверочные сайты — проверьте интернет")
	}
	st.Best = st.Results[best].Name
	st.Current = ""
	return startWinws(st.Best, warp)
}

// ---------- обновление ----------
func zapretLatestVersion() (string, error) {
	cl := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}}
	req, _ := http.NewRequest("GET", "https://raw.githubusercontent.com/"+zapretRepo+"/main/.service/version.txt", nil)
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 100))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub ответил %d", resp.StatusCode)
	}
	return strings.TrimSpace(string(b)), nil
}

func zapretDownloadInstall() (string, error) {
	cl := &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{Proxy: nil}}
	urls := []string{}
	if resp, err := cl.Get("https://api.github.com/repos/" + zapretRepo + "/releases/latest"); err == nil {
		var rel struct {
			Tag    string `json:"tag_name"`
			Assets []struct {
				Name string `json:"name"`
				URL  string `json:"browser_download_url"`
			} `json:"assets"`
		}
		json.NewDecoder(resp.Body).Decode(&rel)
		resp.Body.Close()
		for _, a := range rel.Assets {
			if strings.HasSuffix(strings.ToLower(a.Name), ".zip") {
				urls = append(urls, a.URL)
			}
		}
		if rel.Tag != "" {
			urls = append(urls, fmt.Sprintf("https://github.com/%s/releases/download/%s/zapret-discord-youtube-%s.zip", zapretRepo, rel.Tag, rel.Tag))
		}
	}
	if v, err := zapretLatestVersion(); err == nil {
		urls = append(urls, fmt.Sprintf("https://github.com/%s/releases/download/%s/zapret-discord-youtube-%s.zip", zapretRepo, v, v))
	}
	var lastErr error = errors.New("не удалось узнать адрес новой версии")
	for _, u := range urls {
		resp, err := cl.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			lastErr = fmt.Errorf("скачивание: %v %d", err, resp.StatusCode)
			continue
		}
		zdir := zapretDir()
		tmp := zdir + ".new"
		v, err := extractZapretZip(data, tmp)
		if err != nil {
			lastErr = err
			continue
		}
		os.RemoveAll(zdir + ".old")
		if _, err := os.Stat(zdir); err == nil {
			if err := os.Rename(zdir, zdir+".old"); err != nil {
				return "", fmt.Errorf("папка zapret занята: %v", err)
			}
		}
		if err := os.Rename(tmp, zdir); err != nil {
			os.Rename(zdir+".old", zdir)
			return "", err
		}
		os.RemoveAll(zdir + ".old")
		log.Println("запрет обновлён до", v)
		return v, nil
	}
	return "", lastErr
}

// ---------- WARP (официальный клиент Cloudflare) ----------
func warpCLI() string {
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), `Cloudflare\Cloudflare WARP\warp-cli.exe`),
		filepath.Join(os.Getenv("ProgramW6432"), `Cloudflare\Cloudflare WARP\warp-cli.exe`),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

var warpNoTos bool // старые версии warp-cli не знают --accept-tos

func warpExec(args ...string) (string, error) {
	cli := warpCLI()
	if cli == "" {
		return "", errors.New("Cloudflare WARP не установлен")
	}
	run := func(a []string) (string, error) {
		out, err := hiddenCmd(cli, a...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	var out string
	var err error
	if !warpNoTos {
		out, err = run(append([]string{"--accept-tos"}, args...))
		if err != nil && strings.Contains(strings.ToLower(out), "accept-tos") {
			warpNoTos = true
		}
	}
	if warpNoTos {
		out, err = run(args)
	}
	if len(args) > 0 && args[0] != "status" && args[0] != "--version" {
		log.Printf("warp-cli %s → %v: %s", strings.Join(args, " "), err, out)
	}
	return out, err
}

func warpConnected() bool {
	out, err := warpExec("status")
	return err == nil && strings.Contains(out, "Connected") && !strings.Contains(out, "Disconnected")
}

func warpVersion() string {
	out, err := warpExec("--version")
	if err != nil {
		return ""
	}
	return reVer.FindString(out)
}

var reVer = regexp.MustCompile(`\d{4}\.\d+\.\d+\.\d+`)

const warpMSIURL = "https://downloads.cloudflareclient.com/v1/download/windows/ga"

// Последняя версия WARP: по адресу, на который перенаправляет ссылка на загрузку.
func warpLatest() (version, key string, err error) {
	cl := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Head(warpMSIURL)
	if err != nil {
		return "", "", err
	}
	resp.Body.Close()
	final := resp.Request.URL.String()
	key = final + "|" + resp.Header.Get("ETag") + "|" + resp.Header.Get("Content-Length")
	version = reVer.FindString(final)
	if version == "" {
		version = reVer.FindString(resp.Header.Get("Content-Disposition"))
	}
	return version, key, nil
}

// Выполняется с правами администратора: скачать MSI и тихо установить.
func warpInstall(st *zState) error {
	cl := &http.Client{Timeout: 20 * time.Minute, Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Get(warpMSIURL)
	if err != nil {
		return fmt.Errorf("не удалось скачать WARP: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("сервер WARP ответил %d", resp.StatusCode)
	}
	msi := filepath.Join(os.TempDir(), "Cloudflare_WARP.msi")
	f, err := os.Create(msi)
	if err != nil {
		return err
	}
	st.Total = int(resp.ContentLength >> 20)
	buf := make([]byte, 1<<20)
	var got int64
	last := time.Now()
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			f.Write(buf[:n])
			got += int64(n)
			if time.Since(last) > time.Second {
				st.Done = int(got >> 20)
				writeJSONFile(zStatePath(), st)
				last = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return fmt.Errorf("обрыв при скачивании WARP: %v", rerr)
		}
	}
	f.Close()
	defer os.Remove(msi)
	st.Phase = "warp-setup"
	writeJSONFile(zStatePath(), st)
	cmd := hiddenCmd("msiexec", "/i", msi, "/qn", "/norestart")
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || (ee.ExitCode() != 3010 && ee.ExitCode() != 1641) {
			return fmt.Errorf("установка WARP не удалась: %v", err)
		}
	}
	key := resp.Request.URL.String() + "|" + resp.Header.Get("ETag") + "|" + resp.Header.Get("Content-Length")
	os.WriteFile(filepath.Join(dataDir, "warp-release.txt"), []byte(key), 0644)
	for i := 0; i < 30 && warpCLI() == ""; i++ {
		time.Sleep(time.Second)
	}
	return nil
}

func warpExclude() {
	for _, d := range bypassList {
		if _, err := warpExec("tunnel", "host", "add", d); err != nil {
			warpExec("add-excluded-domain", d) // старые версии
		}
	}
}

func warpStatus() string {
	out, _ := warpExec("status")
	return out
}

// Ход подключения WARP (показывается в окне).

// Подключение WARP с максимальной совместимостью: текущие настройки, затем MASQUE на разных
// портах, затем WireGuard на разных портах — пока какой-то вариант не пройдёт.
var errWarpCanceled = errors.New("подключение WARP отменено")

func warpConnect() error {
	warpCancel.Store(false)
	defer warpStage.Store("")
	warpExclude()
	// служба WARP могла быть остановлена/отключена (после обновления Windows, «оптимизаторов»
	// или ручного выхода из клиента) — тогда warp-cli не отвечает и подключение не идёт
	warpStage.Store("запуск службы")
	if out, _ := hiddenCmd("sc", "query", "CloudflareWARP").CombinedOutput(); !strings.Contains(string(out), "RUNNING") {
		hiddenCmd("sc", "config", "CloudflareWARP", "start=", "auto").Run()
		hiddenCmd("sc", "start", "CloudflareWARP").Run()
		for i := 0; i < 15; i++ {
			if _, err := warpExec("status"); err == nil {
				break
			}
			time.Sleep(time.Second)
		}
		log.Println("служба WARP запущена")
	}
	warpStage.Store("регистрация")
	if out, err := warpExec("registration", "show"); err != nil || strings.Contains(strings.ToLower(out), "missing") || strings.Contains(strings.ToLower(out), "error") {
		if out, err := warpExec("registration", "new"); err != nil {
			if out2, err2 := warpExec("register"); err2 != nil { // старые версии клиента
				return fmt.Errorf("WARP не смог зарегистрироваться (серверы Cloudflare недоступны): %s", firstLine(out+" "+out2))
			}
		}
	}
	warpExec("mode", "warp")
	warpGUIStart()
	last := ""
	try := func(label string, secs int) bool {
		if warpCancel.Load() {
			return false
		}
		warpStage.Store(label)
		warpExec("connect")
		for i := 0; i < secs; i++ {
			time.Sleep(time.Second)
			if warpCancel.Load() {
				return false
			}
			st := warpStatus()
			last = st
			if strings.Contains(st, "Connected") && !strings.Contains(st, "Disconnected") && !strings.Contains(st, "Connecting") {
				log.Println("WARP подключён:", label)
				return true
			}
			// клиент сам бросил попытку — просим ещё раз (не чаще раза в 6 секунд, иначе он
			// каждый раз начинает «happy eyeballs» заново и не успевает подключиться)
			if strings.Contains(st, "Disconnected") && !strings.Contains(st, "Manual") && i%6 == 5 {
				warpExec("connect")
			}
		}
		log.Printf("WARP (%s) не подключился: %s", label, last)
		return false
	}
	if try("текущие настройки", 20) {
		return nil
	}
	if warpCancel.Load() {
		return errWarpCanceled
	}
	type variant struct{ proto, endpoint string }
	variants := []variant{
		{"MASQUE", ""},
		{"MASQUE", "162.159.198.1:443"},
		{"MASQUE", "162.159.198.2:4443"},
		{"MASQUE", "162.159.198.2:8443"},
		{"MASQUE", "162.159.198.2:8095"},
		{"WireGuard", ""},
		{"WireGuard", "162.159.192.1:2408"},
		{"WireGuard", "162.159.192.1:500"},
		{"WireGuard", "162.159.192.1:1701"},
		{"WireGuard", "162.159.192.1:4500"},
		{"WireGuard", "162.159.195.1:2408"},
	}
	for _, v := range variants {
		if warpCancel.Load() {
			return errWarpCanceled
		}
		warpExec("disconnect")
		warpExec("tunnel", "protocol", "set", v.proto)
		if v.endpoint == "" {
			warpExec("tunnel", "endpoint", "reset")
		} else if _, err := warpExec("tunnel", "endpoint", "set", v.endpoint); err != nil {
			continue // эта версия клиента не умеет задавать адрес — пропускаем вариант
		}
		time.Sleep(4 * time.Second) // клиент применяет настройку (иначе сам рвёт попытку: «Settings Changed»)
		label := v.proto
		if v.endpoint != "" {
			label += " через " + v.endpoint
		}
		if try(label, 20) {
			return nil
		}
	}
	if warpCancel.Load() {
		return errWarpCanceled
	}
	warpExec("disconnect")
	warpExec("tunnel", "endpoint", "reset")
	warpExec("tunnel", "protocol", "set", "MASQUE")
	reason := firstLine(strings.TrimPrefix(strings.TrimSpace(last), "Status update:"))
	if reason == "" {
		reason = "нет ответа"
	}
	if strings.Contains(last, "MITM") {
		return errors.New("WARP видит, что его подключение искажается по пути: так бывает, если провайдер блокирует WARP или запрет работает ещё и на роутере")
	}
	return fmt.Errorf("WARP не подключился ни одним способом (перепробовано %d вариантов: MASQUE и WireGuard на разных портах). Похоже, провайдер блокирует WARP. Последний ответ: %s", len(variants)+1, reason)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", "")
	parts := strings.Split(s, "\n")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	s = strings.Join(parts, "; ")
	if len([]rune(s)) > 160 {
		s = string([]rune(s)[:160]) + "…"
	}
	return s
}

// Отключить WARP и прервать идущую попытку подключения (перебор вариантов).
func warpDisconnect() {
	warpCancel.Store(true)
	warpExec("disconnect")
}

// Запустить приложение Cloudflare WARP (значок в трее), если оно установлено и не запущено.
func warpGUIStart() {
	cli := warpCLI()
	if cli == "" {
		return
	}
	gui := filepath.Join(filepath.Dir(cli), "Cloudflare WARP.exe")
	if _, err := os.Stat(gui); err != nil {
		return
	}
	if processRunning("Cloudflare WARP.exe") {
		return
	}
	c := exec.Command(gui)
	c.Dir = filepath.Dir(gui)
	if c.Start() == nil {
		go c.Wait()
	}
}

const warpDownloadURL = "https://1.1.1.1/"

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
