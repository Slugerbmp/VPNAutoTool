//go:build !windows

package main

import "errors"

const hotspotSupported = false

type hsState struct {
	State   string `json:"state"`
	Ssid    string `json:"ssid"`
	Pass    string `json:"pass"`
	Clients int    `json:"clients"`
	Error   string `json:"error"`
}

func hotspotPS(string) (hsState, error) {
	return hsState{}, errors.New("раздача доступна только на Windows")
}
func hotspotProxyStart(bool) error {
	return errors.New("раздача доступна только на Windows")
}
func hotspotProxyStop()        {}
func hotspotProxyAddr() string { return "" }
func warpVersion() string      { return "" }
func warpLatest() (string, string, error) {
	return "", "", errors.New("нет")
}

func hotspotIP() string { return "" }
func lanIP() string     { return "" }
