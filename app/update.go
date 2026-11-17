package main

// Автообновление из GitHub Releases: проверка новой версии, скачивание, проверка
// контрольной суммы (SHA256SUMS.txt из того же выпуска) и тихая установка поверх.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Репозиторий с выпусками (владелец/имя).
var updateRepo = "Slugerbmp/VPNAutoTool"

var updateAPI = "https://api.github.com"

const (
	assetWin = "VPN-Auto-Setup.exe"
	assetMac = "VPN-Auto-macOS.zip"
	assetSum = "SHA256SUMS.txt"
)

var upd = struct {
	sync.Mutex
	latest   string // версия последнего выпуска (без «v»)
	notes    string
	page     string
	urls     map[string]string // имя файла → ссылка
	checked  time.Time
	busy     bool
	stage    string
	err      string
	progress float64
}{}

// Клиент: напрямую, а если не вышло — через включённый VPN.
func (a *App) updClients() []*http.Client {
	cl := []*http.Client{{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: nil}}}
	a.mu.Lock()
	px := a.proxyForCur()
	a.mu.Unlock()
	if px != "" {
		pu, _ := url.Parse(px)
		cl = append(cl, &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}})
	}
	return cl
}

func (a *App) updGet(u string) (*http.Response, error) {
	var last error
	for _, c := range a.updClients() {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "VPN-Auto/"+appVersion)
		resp, err := c.Do(req)
		if err == nil && resp.StatusCode == 200 {
			return resp, nil
		}
		if err == nil {
			resp.Body.Close()
			err = fmt.Errorf("ответ %d", resp.StatusCode)
		}
		last = err
	}
	return nil, last
}

func (a *App) checkUpdate() error {
	resp, err := a.updGet(updateAPI + "/repos/" + updateRepo + "/releases/latest")
	if err != nil {
		upd.Lock()
		upd.err, upd.checked = "не удалось проверить обновления: "+err.Error(), time.Now()
		upd.Unlock()
		return err
	}
	defer resp.Body.Close()
	var r struct {
		Tag    string `json:"tag_name"`
		Body   string `json:"body"`
		Page   string `json:"html_url"`
		Draft  bool   `json:"draft"`
		Pre    bool   `json:"prerelease"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&r); err != nil {
		return err
	}
	urls := map[string]string{}
	for _, as := range r.Assets {
		urls[as.Name] = as.URL
	}
	upd.Lock()
	upd.latest, upd.notes, upd.page, upd.urls, upd.checked, upd.err = strings.TrimPrefix(r.Tag, "v"), r.Body, r.Page, urls, time.Now(), ""
	upd.Unlock()
	return nil
}

func updAvailable() (string, bool) {
	upd.Lock()
	defer upd.Unlock()
	return upd.latest, upd.latest != "" && versionNewer(strings.TrimPrefix(upd.latest, "v"), appVersion)
}

// Фоновая проверка: через минуту после запуска и затем каждые 6 часов.
// С включённым автообновлением ставит новую версию сама.
func (a *App) updater() {
	time.Sleep(time.Minute)
	for {
		if a.checkUpdate() == nil {
			if v, ok := updAvailable(); ok {
				a.mu.Lock()
				auto := !a.settings.NoAutoUpdate
				a.mu.Unlock()
				if auto {
					log.Println("автообновление до", v)
					if err := a.installUpdate(); err != nil {
						log.Println("обновление:", err)
					}
				} else {
					a.setEvent("доступна новая версия " + v + " — «Настройки» → «Обновить»")
				}
			}
		}
		time.Sleep(6 * time.Hour)
	}
}

func readSums(body io.Reader) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(body)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 {
			m[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return m
}

// Скачать, проверить и запустить установку новой версии.
func (a *App) installUpdate() error {
	upd.Lock()
	if upd.busy {
		upd.Unlock()
		return errors.New("обновление уже идёт")
	}
	upd.busy, upd.err, upd.stage, upd.progress = true, "", "скачиваю", 0
	urls := upd.urls
	ver := upd.latest
	upd.Unlock()
	fail := func(err error) error {
		upd.Lock()
		upd.busy, upd.err, upd.stage = false, err.Error(), ""
		upd.Unlock()
		return err
	}
	asset := assetWin
	if runtime.GOOS == "darwin" {
		asset = assetMac
	}
	if urls[asset] == "" || urls[assetSum] == "" {
		return fail(errors.New("в выпуске " + ver + " нет файла " + asset + " или " + assetSum))
	}
	// контрольные суммы — чтобы не поставить битый или подменённый файл
	sr, err := a.updGet(urls[assetSum])
	if err != nil {
		return fail(err)
	}
	sums := readSums(io.LimitReader(sr.Body, 1<<20))
	sr.Body.Close()
	want := sums[asset]
	if len(want) != 64 {
		return fail(errors.New("нет контрольной суммы для " + asset))
	}
	resp, err := a.updGet(urls[asset])
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	dir := filepath.Join(dataDir, "update")
	os.RemoveAll(dir)
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, asset)
	f, err := os.Create(path)
	if err != nil {
		return fail(err)
	}
	h := sha256.New()
	total := resp.ContentLength
	var done int64
	buf := make([]byte, 256<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			f.Write(buf[:n])
			h.Write(buf[:n])
			done += int64(n)
			if total > 0 {
				upd.Lock()
				upd.progress = float64(done) / float64(total)
				upd.Unlock()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return fail(rerr)
		}
	}
	f.Close()
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(path)
		return fail(errors.New("контрольная сумма не совпала — файл повреждён, обновление отменено"))
	}
	upd.Lock()
	upd.stage = "устанавливаю"
	upd.Unlock()
	log.Println("обновление", ver, "скачано и проверено, запускаю установку")
	if err := runUpdateInstaller(path); err != nil {
		return fail(err)
	}
	// установщик сам закроет программу и запустит новую версию; выходим аккуратно
	go func() { time.Sleep(500 * time.Millisecond); shutdown() }()
	return nil
}

func (a *App) updateView() map[string]any {
	a.mu.Lock()
	auto := !a.settings.NoAutoUpdate
	a.mu.Unlock()
	upd.Lock()
	defer upd.Unlock()
	v := map[string]any{"current": appVersion, "latest": upd.latest, "auto": auto, "busy": upd.busy, "stage": upd.stage,
		"error": upd.err, "progress": upd.progress, "page": upd.page, "repo": updateRepo}
	v["available"] = upd.latest != "" && versionNewer(strings.TrimPrefix(upd.latest, "v"), appVersion)
	if !upd.checked.IsZero() {
		v["checked"] = upd.checked.Format("15:04")
	}
	return v
}

func (a *App) updateRoutes(m *http.ServeMux) {
	m.HandleFunc("/api/update", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Do   string
			Auto *bool
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Auto != nil {
			a.mu.Lock()
			a.settings.NoAutoUpdate = !*req.Auto
			a.saveSettings()
			a.mu.Unlock()
		}
		switch req.Do {
		case "check":
			a.checkUpdate()
		case "install":
			if _, ok := updAvailable(); ok {
				go a.installUpdate()
			}
		}
		writeJSON(w, a.updateView())
	})
}
