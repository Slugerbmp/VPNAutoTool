package main

// Общая (кроссплатформенная) часть модуля Zapret: разбор стратегий из .bat,
// наши списки доменов/IP, распаковка релиза. Запуск winws — в zapret_windows.go.

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

const zapretRepo = "Flowseal/zapret-discord-youtube"

// Сайты, которые программа не трогает ни в одном режиме (VPN, запрет, WARP).
var defaultBypass = []string{"lolka.app"}
var bypassList = append([]string{}, defaultBypass...)

// IP-адреса VPN-серверов: запрет не должен трогать подключения к ним
// (иначе он ломает REALITY-подключения, замаскированные под google.com и т.п.).
var vpnServerIPs []string

// Свои сайты пользователя, которые запрет должен обходить (раздел «Запрет»).
var zapretExtra []string

func bypassProxyOverride() string { // для Windows ProxyOverride
	s := ""
	for _, d := range bypassList {
		s += ";*." + d + ";" + d
	}
	return s
}

// Дополнительные домены (Кинопаб, Instagram, Telegram) — подмешиваются ко всем стратегиям.
var vpnautoDomains = []string{
	// TikTok
	"tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokv.eu", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com",
	"tiktokw.us", "tiktokw.eu", "tiktokd.org", "tiktokd.net", "tik-tokapi.com", "ttwstatic.com", "musical.ly", "muscdn.com",
	"byteoversea.com", "byteoversea.net", "ibytedtos.com", "ibyteimg.com", "ipstatp.com", "bytefcdn-oversea.com",
	"byteintlapi.com", "bytegecko-i18n.com", "isnssdk.com", "sgsnssdk.com", "tiktokrow-cdn.com", "tiktokeu-cdn.com", "ttlivecdn.com",
	// Кинопаб
	"kino.pub", "kino.watch", "kinopub.me", "kinopub.com", "kinopub.ru", "kinopub.tv", "kinopub.net", "kinopub.io", "service-kp.com",
	// Instagram / Meta
	"instagram.com", "cdninstagram.com", "instagr.am", "ig.me", "igcdn.com", "igsonar.com",
	"fbcdn.net", "facebook.com", "facebook.net", "fb.com", "fb.me", "fbsbx.com", "threads.net", "threads.com",
	// Telegram
	"telegram.org", "t.me", "telegram.me", "telegram.dog", "telegra.ph", "telesco.pe", "tdesktop.com",
	"telegram-cdn.org", "cdn-telegram.org", "tg.dev", "graph.org", "fragment.com", "comments.app",
	"contest.com", "usercontent.dev", "telegram.space", "ton.org",
}

// Официальные подсети Telegram (core.telegram.org/resources/cidr.txt) — приложение ходит по IP.
var telegramCIDRs = []string{
	"91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
	"91.108.20.0/22", "91.108.56.0/22", "149.154.160.0/20", "185.76.151.0/24",
	"2001:67c:4e8::/48", "2001:b28:f23c::/48", "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2a0a:f280::/32",
}

// Адреса и порты серверов Cloudflare WARP — для профиля, пропускающего подключение WARP.
var warpCIDRs = []string{
	"162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", "162.159.197.0/24", "162.159.198.0/24",
	"2606:4700:d0::/48", "2606:4700:d1::/48",
}

const warpUDPPorts = "500,854,859,864,878,880,890,891,894,903,908,928,934,939,942,943,945,946,955,968,987,988," +
	"1002,1010,1014,1018,1070,1074,1180,1387,1701,1843,2371,2408,2506,3138,3476,3581,3854,4177,4198,4233,4500," +
	"5279,5956,7103,7152,7156,7281,7559,8319,8742,8854,8886,4443,8443,8095"

// Сайты для подбора лучшей стратегии.
var zapretTargets = []string{
	"https://www.youtube.com", "https://i.ytimg.com", "https://redirector.googlevideo.com",
	"https://discord.com", "https://gateway.discord.gg", "https://cdn.discordapp.com",
	"https://www.instagram.com", "https://static.cdninstagram.com",
	"https://kino.pub", "https://telegram.org", "https://web.telegram.org",
}

type zResult struct {
	Name string `json:"name"`
	OK   int    `json:"ok"`
	Of   int    `json:"of"`
	Ms   int    `json:"ms"`
}

func zapretVersionOf(zdir string) string {
	for _, f := range []string{"vpnauto-version.txt", filepath.Join(".service", "version.txt")} {
		if b, err := os.ReadFile(filepath.Join(zdir, f)); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(zdir, "service.bat")); err == nil {
		if m := regexp.MustCompile(`LOCAL_VERSION=([^"\r\n]+)`).FindSubmatch(b); m != nil {
			return strings.TrimSpace(string(m[1]))
		}
	}
	return ""
}

// Сравнение версий вида 1.10.4 / 1.9.7b
func versionNewer(remote, local string) bool {
	if remote == "" || local == "" {
		return remote != "" && local == ""
	}
	num := regexp.MustCompile(`\d+|[^\d.]+`)
	r, l := num.FindAllString(remote, -1), num.FindAllString(local, -1)
	for i := 0; i < len(r) || i < len(l); i++ {
		var a, b string
		if i < len(r) {
			a = r[i]
		}
		if i < len(l) {
			b = l[i]
		}
		ai, ea := strconv.Atoi(a)
		bi, eb := strconv.Atoi(b)
		if ea == nil && eb == nil {
			if ai != bi {
				return ai > bi
			}
			continue
		}
		if a != b {
			return a > b
		}
	}
	return false
}

// Натуральная сортировка: general, ALT, ALT2 … ALT13, …
func naturalKey(s string) string {
	return regexp.MustCompile(`\d+`).ReplaceAllStringFunc(strings.ToLower(s), func(d string) string {
		return fmt.Sprintf("%08s", d)
	})
}

func listStrategies(zdir string) []string {
	ents, _ := os.ReadDir(zdir)
	var out []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(n), ".bat") || strings.HasPrefix(strings.ToLower(n), "service") {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(zdir, n)); err == nil && bytes.Contains(b, []byte("winws.exe")) {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return naturalKey(out[i]) < naturalKey(out[j]) })
	return out
}

func strategyTitle(file string) string {
	t := strings.TrimSuffix(file, filepath.Ext(file))
	return t
}

// Собирает командную строку winws.exe из .bat-стратегии Flowseal.
func buildCmdline(zdir, strategy string, warp bool) (string, error) {
	b, err := os.ReadFile(filepath.Join(zdir, strategy))
	if err != nil {
		return "", fmt.Errorf("стратегия %s не найдена", strategy)
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")
	start := -1
	for i, l := range lines {
		if strings.Contains(l, `winws.exe"`) {
			start = i
			break
		}
	}
	if start < 0 {
		return "", errors.New("в стратегии нет запуска winws.exe")
	}
	var sb strings.Builder
	for i := start; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], " \t")
		cont := strings.HasSuffix(l, "^")
		l = strings.TrimSuffix(l, "^")
		sb.WriteString(l)
		sb.WriteString(" ")
		if !cont {
			break
		}
	}
	full := sb.String()
	args := full[strings.Index(full, `winws.exe"`)+len(`winws.exe"`):]

	bin := filepath.Join(zdir, "bin") + `\`
	lists := filepath.Join(zdir, "lists") + `\`
	args = strings.NewReplacer(
		"%BIN%", bin, "%LISTS%", lists, "%~dp0", zdir+`\`,
		"%GameFilterTCP%", "12", "%GameFilterUDP%", "12", "%GameFilter%", "12",
	).Replace(args)

	// наши домены и IP — рядом с основными списками
	ipx := `--ipset-exclude="` + lists + `ipset-exclude.txt"`
	args = strings.ReplaceAll(args, ipx, ipx+` --ipset-exclude="`+lists+`ipset-exclude-vpnauto.txt"`)
	ex := `--hostlist-exclude="` + lists + `list-exclude.txt"`
	args = strings.ReplaceAll(args, ex, ex+` --hostlist-exclude="`+lists+`list-exclude-vpnauto.txt"`)
	gen := `--hostlist="` + lists + `list-general.txt"`
	args = strings.ReplaceAll(args, gen, gen+` --hostlist="`+lists+`list-vpnauto.txt"`)
	if st, err := os.Stat(filepath.Join(zdir, "lists", "ipset-all.txt")); err == nil && st.Size() > 0 {
		ip := `--ipset="` + lists + `ipset-all.txt"`
		args = strings.ReplaceAll(args, ip, ip+` --ipset="`+lists+`ipset-vpnauto.txt"`)
	}

	if warp && !warpExcludeMode {
		// WARP через запрет проходит благодаря общим правилам для адресов Cloudflare (ipset-all).
		// Если в service.bat фильтр по IP выключен (вместо списка — заглушка), для WARP берём
		// полный список из резервной копии — как при ручном запуске .bat со включённым ipset.
		all := filepath.Join(zdir, "lists", "ipset-all.txt")
		if st, err := os.Stat(all); err == nil && st.Size() < 200 {
			if bk, err := os.Stat(all + ".backup"); err == nil && bk.Size() > 1000 {
				args = strings.ReplaceAll(args, `ipset-all.txt"`, `ipset-all.txt.backup"`)
			}
		}
	}
	if warp && warpExcludeMode {
		// запасной режим: серверы WARP исключены из общих правил — отдельный профиль только для
		// рукопожатия WireGuard (порты WARP — в перехват, профиль — первым)
		args = regexp.MustCompile(`--wf-udp=(\S+)`).ReplaceAllString(args, "--wf-udp=${1},"+warpUDPPorts)
		// только рукопожатие WireGuard (UDP, не 443); TLS/MASQUE не трогаем — иначе WARP видит
		// подмену пакетов (CF_HAPPY_EYEBALLS_MITM_FAILURE)
		prof := `--filter-udp=` + warpUDPPorts + ` --ipset="` + lists + `ipset-warp.txt" --dpi-desync=fake --dpi-desync-any-protocol=1 ` +
			`--dpi-desync-repeats=6 --dpi-desync-cutoff=n2 --dpi-desync-fake-unknown-udp="` + bin + `ACTIVE_GAME_UDP.bin" --new `
		if i := strings.Index(args, "--filter-"); i >= 0 {
			args = args[:i] + prof + args[i:]
		}
	}
	if m := regexp.MustCompile(`%[A-Za-z~][A-Za-z0-9_]*%`).FindString(args); m != "" {
		return "", fmt.Errorf("в стратегии осталась неизвестная переменная %s", m)
	}
	return `"` + bin + `winws.exe" ` + strings.Join(strings.Fields(args), " "), nil
}

func writeZapretLists(zdir string) error {
	ld := filepath.Join(zdir, "lists")
	if err := os.MkdirAll(ld, 0755); err != nil {
		return err
	}
	excl := bypassList
	if len(excl) == 0 {
		excl = []string{"domain.example.abc"}
	}
	files := map[string][]string{
		"list-exclude-vpnauto.txt": excl,
		"list-vpnauto.txt":         append(append([]string{}, vpnautoDomains...), zapretExtra...),
		"ipset-vpnauto.txt":        telegramCIDRs,
		"ipset-warp.txt":           warpCIDRs,
		"ipset-exclude-vpnauto.txt": func() []string {
			// серверы VPN запрет не трогает; серверы WARP — только в запасном режиме
			ips := append([]string{}, vpnServerIPs...)
			if warpExcludeMode {
				ips = append(ips, warpCIDRs...)
			}
			if len(ips) == 0 {
				ips = []string{"203.0.113.114/32"} // пустой список winws не принимает
			}
			return ips
		}(),
	}
	for name, lines := range files {
		if err := os.WriteFile(filepath.Join(ld, name), []byte(strings.Join(lines, "\r\n")+"\r\n"), 0644); err != nil {
			return err
		}
	}
	// файлы, которые ждут стратегии Flowseal (обычно их создаёт service.bat)
	for name, def := range map[string]string{
		"list-general-user.txt":  "# Never leave this file empty\r\ndomain.example.abc\r\n",
		"list-exclude-user.txt":  "domain.example.abc\r\n",
		"ipset-exclude-user.txt": "203.0.113.113/32\r\n",
	} {
		p := filepath.Join(ld, name)
		if _, err := os.Stat(p); err != nil {
			os.WriteFile(p, []byte(def), 0644)
		}
	}
	return nil
}

// Распаковывает релиз (zip) в dst. Возвращает версию.
func extractZapretZip(data []byte, dst string) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", errors.New("архив запрета повреждён")
	}
	prefix := ""
	found := false
	for _, f := range zr.File {
		n := strings.ReplaceAll(f.Name, `\`, "/")
		if strings.HasSuffix(strings.ToLower(n), "bin/winws.exe") {
			prefix = strings.TrimSuffix(n, "bin/winws.exe")
			prefix = n[:len(prefix)]
			found = true
			break
		}
	}
	if !found {
		return "", errors.New("в архиве нет bin/winws.exe")
	}
	os.RemoveAll(dst)
	for _, f := range zr.File {
		n := strings.ReplaceAll(f.Name, `\`, "/")
		if !strings.HasPrefix(n, prefix) {
			continue
		}
		rel := strings.TrimPrefix(n, prefix)
		if rel == "" || strings.HasPrefix(rel, ".github") || strings.Contains(rel, "..") {
			continue
		}
		target := filepath.Join(dst, filepath.FromSlash(path.Clean(rel)))
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		w, err := os.Create(target)
		if err != nil {
			rc.Close()
			return "", err
		}
		_, err = io.Copy(w, rc)
		rc.Close()
		w.Close()
		if err != nil {
			return "", err
		}
	}
	v := zapretVersionOf(dst)
	if v != "" {
		os.WriteFile(filepath.Join(dst, "vpnauto-version.txt"), []byte(v), 0644)
	}
	return v, writeZapretLists(dst)
}

// Адрес сервера из outbound Xray.
func serverAddr(ob map[string]any) string {
	st, _ := ob["settings"].(map[string]any)
	for _, k := range []string{"vnext", "servers"} {
		if arr, ok := st[k].([]any); ok && len(arr) > 0 {
			if m, ok := arr[0].(map[string]any); ok {
				if a, ok := m["address"].(string); ok {
					return a
				}
			}
		}
	}
	if a, ok := st["address"].(string); ok {
		return a
	}
	return ""
}

func resolveServerIPs(servers []*Server) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range servers {
		host := serverAddr(s.Outbound)
		if host == "" {
			continue
		}
		ips := []net.IP{}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else if r, err := net.LookupIP(host); err == nil {
			ips = r
		}
		for _, ip := range ips {
			c := ip.String() + "/32"
			if ip.To4() == nil {
				c = ip.String() + "/128"
			}
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// Запасной режим WARP (см. zCmd.WarpExclude): в задаче — из команды, в программе — после ошибки MITM.
var warpExcludeMode bool
var appWarpExclude atomic.Bool

// Отмена перебора вариантов WARP (выключили WARP или переключились на VPN).
var warpCancel atomic.Bool

// Ход подключения WARP (показывается в окне); пишется из фоновой задачи — поэтому атомарно.
var warpStage atomicString

type atomicString struct{ v atomic.Value }

func (s *atomicString) Store(x string) { s.v.Store(x) }
func (s *atomicString) Load() string {
	x, _ := s.v.Load().(string)
	return x
}
