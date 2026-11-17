package main

// «Починить файлы»: проверить всё, что программа скачивает и создаёт, и восстановить
// то, что пропало (обычно — удалено антивирусом): ядро Xray, запрет, задачу запуска,
// TG WS Proxy, WARP, значок и ярлык, исключения Защитника. Потом перезапустить нужное.

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed icon.ico
var appIconData []byte

var repair = struct {
	sync.Mutex
	busy  bool
	lines []string
	done  time.Time
}{}

func repairLog(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	log.Println("починка:", s)
	repair.Lock()
	repair.lines = append(repair.lines, s)
	repair.Unlock()
}

func (a *App) repairAll() {
	repair.Lock()
	if repair.busy {
		repair.Unlock()
		return
	}
	repair.busy, repair.lines = true, nil
	repair.Unlock()
	defer func() {
		repair.Lock()
		repair.busy, repair.done = false, time.Now()
		repair.Unlock()
	}()
	fixed := 0

	// 1. Ядро VPN (Xray), включая совместимую версию, если она используется
	if _, err := os.Stat(coreExe()); err != nil {
		repairLog("ядро VPN отсутствует — скачиваю")
		stopCore()
		if err := ensureCore(); err != nil {
			repairLog("⚠ ядро не скачалось: %v", err)
		} else {
			repairLog("✓ ядро VPN восстановлено")
			fixed++
			a.mu.Lock()
			servers := append([]*Server(nil), a.servers...)
			a.cfg = nil
			a.mu.Unlock()
			if len(servers) > 0 {
				a.loadMu.Lock()
				a.applyServers(servers)
				a.loadMu.Unlock()
			}
		}
	} else {
		repairLog("✓ ядро VPN на месте")
	}

	if runtime.GOOS == "windows" {
		// 2. Значок (на диске C:) — для «Пуска», панели задач и списка программ
		ico := filepath.Join(dataDir, "NETtool.ico")
		if b, err := os.ReadFile(ico); err != nil || len(b) != len(appIconData) {
			os.WriteFile(ico, appIconData, 0644)
			repairLog("✓ значок восстановлен")
			fixed++
		}
		// 3. Ярлык в «Пуске»
		if repairShortcut(ico) {
			repairLog("✓ ярлык NETtool в «Пуске» восстановлен")
			fixed++
		} else {
			repairLog("✓ ярлык в «Пуске» на месте")
		}

		// 4. Запрет: файлы и задача запуска без UAC
		if zapretSupported {
			if !zapretInstalled() || !zapretFilesOK() {
				repairLog("файлы запрета повреждены или удалены — скачиваю заново")
				if zapretTaskExists() {
					if _, err := zapretRun(zCmd{Action: "update"}, 3*time.Minute); err != nil {
						repairLog("⚠ запрет не восстановился: %v", err)
					}
				} else if err := zapretEnsureTask(); err != nil { // создаст задачу и скачает запрет (один запрос UAC)
					repairLog("⚠ %v", err)
				}
				if zapretInstalled() && zapretFilesOK() {
					repairLog("✓ запрет восстановлен")
					fixed++
				}
			} else {
				repairLog("✓ файлы запрета на месте")
			}
			if zapretInstalled() && !zapretTaskExists() {
				if err := zapretEnsureTask(); err != nil {
					repairLog("⚠ задача запуска запрета: %v", err)
				} else {
					repairLog("✓ задача запуска запрета восстановлена")
					fixed++
				}
			}
		}

		// 5. TG WS Proxy
		a.mu.Lock()
		tgOn, warpOn := a.settings.TgOn, a.settings.Warp
		a.mu.Unlock()
		if tgwsSupported && tgOn && !tgwsInstalled() {
			if _, err := tgwsInstall(); err != nil {
				repairLog("⚠ TG WS Proxy не скачался: %v", err)
			} else {
				repairLog("✓ TG WS Proxy восстановлен")
				fixed++
			}
		}

		// 6. WARP (если включён в настройках, а клиент пропал)
		if warpOn && warpCLI() == "" {
			repairLog("клиент WARP отсутствует — устанавливаю")
			if a.warpInstallSync() {
				repairLog("✓ WARP переустановлен")
				fixed++
			} else {
				repairLog("⚠ WARP не установился")
			}
		}

		// 7. Исключения Защитника — если пользователь на них соглашался
		if _, err := os.Stat(filepath.Join(dataDir, "defender-on")); err == nil && zapretTaskExists() {
			if _, err := zapretRun(zCmd{Action: "defender"}, 60*time.Second); err == nil {
				repairLog("✓ исключения Защитника обновлены")
			}
		}
		if av := installedAV(); len(av) > 0 {
			var other []string
			for _, n := range av {
				if !strings.Contains(strings.ToLower(n), "defender") {
					other = append(other, n)
				}
			}
			if len(other) > 0 {
				repairLog("установлен %s — если файлы снова пропадут, добавьте NETtool в его исключения", strings.Join(other, ", "))
			}
		}

		// 8. Вернуть работу запрета, если он должен быть включён
		if zapretSupported && a.mode() == "zapret" && zapretInstalled() && !winwsRunning() {
			a.mu.Lock()
			last := a.settings.LastOn
			a.mu.Unlock()
			if last {
				if err := a.zapretOn(); err == nil {
					repairLog("✓ запрет снова включён")
				}
			}
		}
	}
	if fixed == 0 {
		repairLog("всё в порядке — чинить нечего")
	} else {
		repairLog("готово: восстановлено %d", fixed)
		a.setEvent(fmt.Sprintf("починка файлов: восстановлено %d", fixed))
	}
}

func (a *App) repairRoutes(m *http.ServeMux) {
	m.HandleFunc("/api/repair", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req struct{ Start bool }
			json.NewDecoder(r.Body).Decode(&req)
			if req.Start {
				go a.repairAll()
				time.Sleep(100 * time.Millisecond)
			}
		}
		repair.Lock()
		defer repair.Unlock()
		writeJSON(w, map[string]any{"busy": repair.busy, "lines": repair.lines})
	})
}

// ensureShortcut — при каждом запуске: значок на диске C:, ярлык в «Пуске» ведёт на текущий exe
// и связан с окном приложения.
func ensureShortcut() {
	if runtime.GOOS != "windows" {
		return
	}
	ico := filepath.Join(dataDir, "NETtool.ico")
	if b, err := os.ReadFile(ico); err != nil || len(b) != len(appIconData) {
		os.WriteFile(ico, appIconData, 0644)
	}
	if repairShortcut(ico) {
		log.Printf("ярлык NETtool в «Пуске» пересоздан")
	}
	// закреплённый на панели задач значок — тот же ID, иначе окно открывается отдельной кнопкой
	pinned := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar`)
	for _, n := range []string{"NETtool.lnk", "VPN Auto.lnk"} {
		if p := filepath.Join(pinned, n); fileExistsW(p) {
			lnkSetAUMID(p)
		}
	}
}
