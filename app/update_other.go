//go:build !windows && !darwin

package main

import "errors"

func runUpdateInstaller(string) error {
	return errors.New("автообновление есть только для Windows и macOS")
}
