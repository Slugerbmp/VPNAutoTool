package main

import (
	"os/exec"
	"syscall"
)

// Тихая установка: установщик закроет программу, заменит файлы и запустит новую версию.
func runUpdateInstaller(path string) error {
	cmd := exec.Command(path, "--silent")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200 | 0x00000008} // NEW_PROCESS_GROUP | DETACHED
	return cmd.Start()
}
