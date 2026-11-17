package main

import "os"

// Путь к ядру Xray для тестов совместимости настроек (переменная XRAY_BIN); нет — тесты с ядром пропускаются.
func xrayBin() string {
	if p := os.Getenv("XRAY_BIN"); p != "" {
		return p
	}
	return "/nonexistent/xray"
}
