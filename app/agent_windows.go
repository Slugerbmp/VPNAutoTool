package main

// Помощник с правами администратора. Запускается один раз за сеанс программы (один запрос
// UAC) и выполняет команды запрета, WARP, шлюза и Защитника, пока работает NETtool.
// Так Windows не спрашивает разрешение на каждое нажатие, если задача планировщика
// на этом компьютере не работает.

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

func agentAlivePath() string { return filepath.Join(dataDir, "agent-alive") }

func agentAlive() bool {
	st, err := os.Stat(agentAlivePath())
	return err == nil && time.Since(st.ModTime()) < 3*time.Second
}

func isElevated() bool {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer tok.Close()
	var elev, n uint32
	// TokenElevation = 20
	if err := syscall.GetTokenInformation(tok, 20, (*byte)(unsafe.Pointer(&elev)), 4, &n); err != nil {
		return false
	}
	return elev != 0
}

var (
	agentMu      sync.Mutex
	agentAsked   time.Time
	agentRefused bool
	// пользователь нажал «Нет» в окне UAC
	agentDeclined bool
)

func agentRefusedNow() bool {
	agentMu.Lock()
	defer agentMu.Unlock()
	return agentDeclined && time.Since(agentAsked) < time.Minute
}

// startAgent запускает помощника (если ещё не запущен) и ждёт, пока он ответит.
func startAgent() bool {
	agentMu.Lock()
	defer agentMu.Unlock()
	if agentAlive() {
		return true
	}
	// отказались в окне UAC — не спрашиваем снова минуту, чтобы не засыпать окнами
	if agentRefused && time.Since(agentAsked) < time.Minute {
		return false
	}
	agentAsked = time.Now()
	exe, _ := os.Executable()
	pid := strconv.Itoa(os.Getpid())
	var err error
	if isElevated() {
		err = hiddenCmd(exe, "--admin-agent", pid).Start()
	} else {
		ps := `Start-Process -FilePath ` + psQuote(exe) + ` -ArgumentList '--admin-agent','` + pid + `' -Verb RunAs -WindowStyle Hidden`
		err = hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
	}
	if err != nil {
		agentRefused, agentDeclined = true, true
		log.Println("помощник с правами администратора не запущен:", err)
		return false
	}
	agentDeclined = false
	for i := 0; i < 50; i++ {
		if agentAlive() {
			agentRefused = false
			log.Println("помощник с правами администратора запущен")
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	agentRefused = true
	return false
}

func taskBrokenPath() string { return filepath.Join(dataDir, "task-broken") }

// При запуске программы: если задача планировщика на этом компьютере не работает (или её нет),
// а запрет установлен — спрашиваем права сразу, один раз на весь сеанс. Там, где задача
// работает, окон UAC нет вовсе.
func adminAgentAtStart() {
	if !zapretSupported || !zapretInstalled() {
		return
	}
	_, broken := os.Stat(taskBrokenPath())
	if broken == nil || !zapretTaskExists() {
		startAgent()
	}
}

func adminAgentMain(parentPID string) {
	pid, _ := strconv.Atoi(parentPID)
	// SYNCHRONIZE — чтобы ждать завершения программы
	ph, err := syscall.OpenProcess(0x00100000, false, uint32(pid))
	if err != nil {
		return
	}
	defer syscall.CloseHandle(ph)
	log.Println("помощник запущен, программа", pid)
	alive := agentAlivePath()
	defer os.Remove(alive)

	var last int64
	if b, err := os.ReadFile(zCmdPath()); err == nil {
		var c zCmd
		if json.Unmarshal(b, &c) == nil {
			last = c.Req // старую команду не повторяем
		}
	}
	touch := func() {
		now := time.Now()
		if os.Chtimes(alive, now, now) != nil {
			os.WriteFile(alive, []byte(parentPID), 0644)
		}
	}
	// команды выполняются по очереди в отдельной горутине, а метка «жив» обновляется всегда
	queue := make(chan zCmd, 32)
	go func() {
		for c := range queue {
			zapretHandle(c)
		}
	}()
	for {
		touch()
		if ev, _ := syscall.WaitForSingleObject(ph, 0); ev == 0 { // программа закрыта
			log.Println("программа закрыта — помощник завершается")
			return
		}
		var c zCmd
		if b, err := os.ReadFile(zCmdPath()); err == nil && json.Unmarshal(b, &c) == nil && c.Req != 0 && c.Req != last {
			last = c.Req
			select {
			case queue <- c:
			default:
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
}
