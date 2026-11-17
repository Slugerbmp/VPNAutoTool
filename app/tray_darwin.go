//go:build darwin

package main

import (
	_ "embed"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

//go:embed menubar.js
var menubarJS []byte

//go:embed tray_mac.png
var trayPNG []byte

var (
	trayMu  sync.Mutex
	trayCmd *exec.Cmd
)

func startTray() bool {
	js := filepath.Join(dataDir, "menubar.js")
	icon := filepath.Join(dataDir, "tray.png")
	if os.WriteFile(js, menubarJS, 0644) != nil || os.WriteFile(icon, trayPNG, 0644) != nil {
		return false
	}
	cmd := exec.Command("osascript", "-l", "JavaScript", js, "http://"+uiAddr, icon)
	lf, _ := os.Create(filepath.Join(dataDir, "menubar.log"))
	if lf != nil {
		cmd.Stdout, cmd.Stderr = lf, lf
	}
	if err := cmd.Start(); err != nil {
		log.Println("menubar:", err)
		return false
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	select {
	case <-exited: // скрипт сразу упал — работаем без значка
		log.Println("menubar завершился сразу, см. menubar.log")
		return false
	case <-time.After(2 * time.Second):
	}
	trayMu.Lock()
	trayCmd = cmd
	trayMu.Unlock()
	return true
}

func traySet(bool, string) {} // значок сам опрашивает состояние

func trayRemove() {
	trayMu.Lock()
	defer trayMu.Unlock()
	if trayCmd != nil && trayCmd.Process != nil {
		trayCmd.Process.Kill()
	}
}

func openOrFocusUI() { openUI() }

func afterOpenUI() {}

func closeUIWindows() {
	exec.Command("pkill", "-f", "--", filepath.Join(dataDir, "ui")).Run()
}
