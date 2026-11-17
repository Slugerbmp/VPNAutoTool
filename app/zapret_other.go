//go:build !windows

package main

import (
	"errors"
	"time"
)

// Zapret (winws) есть только для Windows.
const zapretSupported = false
const warpDownloadURL = "https://1.1.1.1/"

type zCmd struct {
	Action      string
	Strategy    string
	Warp        bool
	Bypass      []string
	VPNIPs      []string
	IfIdx       int
	WarpExclude bool
	Extra       []string
}

type zState struct {
	Busy    bool
	Phase   string
	Done    int
	Total   int
	Current string
	Results []zResult
	Best    string
	Error   string
	Version string
}

var errNoZapret = errors.New("Zapret доступен только на Windows")

func zapretDir() string                             { return "" }
func zapretInstalled() bool                         { return false }
func winwsRunning() bool                            { return false }
func readZState() zState                            { return zState{} }
func zapretTaskExists() bool                        { return false }
func zapretSetupTask() error                        { return errNoZapret }
func zapretEnsureTask() error                       { return errNoZapret }
func zapretRun(zCmd, time.Duration) (zState, error) { return zState{}, errNoZapret }
func zapretTaskMain()                               {}
func zapretLatestVersion() (string, error)          { return "", errNoZapret }
func warpCLI() string                               { return "" }
func warpConnected() bool                           { return false }
func warpConnect() error                            { return errNoZapret }
func warpDisconnect()                               {}

func warpExclude() {}

func warpGUIStart()                          {}
func zapretDownloadInstall() (string, error) { return "", errNoZapret }

var errWarpCanceled = errors.New("подключение WARP отменено")

func warpExec(args ...string) (string, error) { return "", errNoZapret }
func defenderExclude() error                  { return errNoZapret }
func psQuote(s string) string                 { return s }
func defenderRefresh()                        {}
func installedAV() []string                   { return nil }
func zapretFilesOK() bool                     { return false }
func repairShortcut(string) bool              { return false }
