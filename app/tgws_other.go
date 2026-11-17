//go:build !windows

package main

import "errors"

const tgwsSupported = false

var errNoTgws = errors.New("TG WS Proxy в программе доступен только на Windows")

func tgwsInstalled() bool            { return false }
func tgwsRunning() bool              { return false }
func tgwsLocalVersion() string       { return "" }
func tgwsInstall() (string, error)   { return "", errNoTgws }
func tgwsStart() error               { return errNoTgws }
func tgwsStop()                      {}
func tgwsLink() string               { return "" }
func tgwsLatestTag() (string, error) { return "", errNoTgws }
func tgwsDir() string                { return "" }
