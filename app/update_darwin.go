package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Замена .app после выхода программы: распаковать архив рядом и подменить пакет.
func runUpdateInstaller(zip string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	i := strings.Index(exe, ".app/")
	if i < 0 {
		return errors.New("программа запущена не из пакета .app — обновите вручную")
	}
	app := exe[:i+4]
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	tmp := filepath.Join(filepath.Dir(zip), "unpacked")
	script := fmt.Sprintf(`while kill -0 %d 2>/dev/null; do sleep 0.5; done
rm -rf %[2]s && mkdir -p %[2]s && ditto -xk %[3]s %[2]s || exit 1
new=$(find %[2]s -maxdepth 2 -name '*.app' -type d | head -1)
[ -n "$new" ] || exit 1
rm -rf %[4]s && mv "$new" %[4]s && xattr -cr %[4]s; open %[4]s`, os.Getpid(), q(tmp), q(zip), q(app))
	cmd := exec.Command("/bin/sh", "-c", script)
	return cmd.Start()
}
