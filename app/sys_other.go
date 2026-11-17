//go:build !windows && !darwin

package main

// Заглушки, чтобы приложение собиралось и проверялось на Linux.

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const coreName = "vpnauto-core"

func hiddenCmd(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }
func setSysProxy(on bool) error                       { log.Println("sysproxy", on); return nil }
func cleanupStaleProxy()                              {}
func killProcess(string)                              {}
func openURL(u string)                                { log.Println("open", u) }
func uninstall()                                      {}
func startTray() bool                                 { return false }
func traySet(bool, string)                            {}
func trayRemove()                                     {}
func openOrFocusUI()                                  { openUI() }
func msgBox(string, uintptr) int                      { return 0 }
func selfInstall() bool                               { return false }
func detach(*exec.Cmd)                                {}
func browserPaths() []string                          { return nil }
func xrayURL() string {
	return "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
}
func defaultDataDir() string {
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		return filepath.Join(d, "VPNAuto")
	}
	return filepath.Join(os.TempDir(), "VPNAuto")
}

func afterOpenUI() {}

func fetchSystem(u, ua string) (string, error) {
	out, err := exec.Command("curl", "-fsSL", "--max-time", "30", "-A", ua, u).Output()
	return string(out), err
}

func openFolder(p string) { exec.Command("xdg-open", p).Start() }

const hotkeySupported = false

func hotkeySet(bool)            {}
func openMini()                 { openUI() }
func notify(title, text string) { log.Println("notify:", title, text) }
func setAutostart(bool) error   { return nil }
func currentNetwork() string    { return "" }

func closeUIWindows() {}
