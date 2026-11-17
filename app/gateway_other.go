//go:build !windows

package main

const gatewaySupported = false

func gatewayMain()                         {}
func gatewayStartElevated(ifIdx int) error { return nil }
func gatewayStopElevated(ifIdx int)        {}
