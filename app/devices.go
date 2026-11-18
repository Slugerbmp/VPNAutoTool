package main

// Подключённые устройства: кто пользуется раздачей (прокси, Telegram, DNS-режим, шлюз),
// когда был последний раз и сколько трафика прошло через компьютер.

import (
	"net"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type devInfo struct {
	IP, Name, MAC string
	Via           map[string]bool
	First, Last   time.Time
	Conns         int64
	bytes         atomic.Int64
	resolving     bool
}

var devs = struct {
	sync.Mutex
	m     map[string]*devInfo
	arpAt time.Time
	arp   map[string]string
}{m: map[string]*devInfo{}}

func devGet(ip string) *devInfo {
	if ip == "" || ip == "127.0.0.1" {
		return nil
	}
	devs.Lock()
	defer devs.Unlock()
	d := devs.m[ip]
	if d == nil {
		d = &devInfo{IP: ip, Via: map[string]bool{}, First: time.Now()}
		devs.m[ip] = d
	}
	return d
}

// devSeen отмечает устройство: ip — адрес в сети, via — чем оно пользуется.
func devSeen(ip, via string, conn bool) *devInfo {
	d := devGet(ip)
	if d == nil {
		return nil
	}
	devs.Lock()
	d.Last = time.Now()
	d.Via[via] = true
	if conn {
		d.Conns++
	}
	need := d.Name == "" && !d.resolving
	if need {
		d.resolving = true
	}
	devs.Unlock()
	if need {
		go func() {
			name := ""
			if ns, err := net.LookupAddr(ip); err == nil && len(ns) > 0 {
				name = strings.TrimSuffix(ns[0], ".")
				if i := strings.IndexByte(name, '.'); i > 0 && !strings.EqualFold(name[i+1:], "local") {
					name = name[:i] // «PS5-123.lan» → «PS5-123»
				} else if i > 0 {
					name = name[:i]
				}
			}
			devs.Lock()
			d.Name, d.resolving = name, false
			if name == "" {
				d.Name = "-"
			}
			devs.Unlock()
		}()
	}
	return d
}

func remoteIP(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	h, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	return h
}

// devConn считает трафик устройства.
type devConn struct {
	net.Conn
	d *devInfo
}

func (c *devConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.d.bytes.Add(int64(n))
	return n, err
}

func (c *devConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.d.bytes.Add(int64(n))
	return n, err
}

// trackConn — отметить устройство и считать его трафик.
func trackConn(c net.Conn, via string) net.Conn {
	if d := devSeen(remoteIP(c), via, true); d != nil {
		return &devConn{c, d}
	}
	return c
}

var reArp = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})`)

func arpTable() map[string]string {
	devs.Lock()
	if time.Since(devs.arpAt) < 30*time.Second && devs.arp != nil {
		m := devs.arp
		devs.Unlock()
		return m
	}
	devs.arpAt = time.Now()
	devs.Unlock()
	m := map[string]string{}
	var out []byte
	if runtime.GOOS == "windows" {
		out, _ = hiddenCmd("arp", "-a").Output()
	} else {
		out, _ = hiddenCmd("arp", "-an").Output()
	}
	for _, x := range reArp.FindAllStringSubmatch(decodeOEM(out), -1) {
		m[x[1]] = strings.ToUpper(strings.ReplaceAll(x[2], "-", ":"))
	}
	devs.Lock()
	devs.arp = m
	devs.Unlock()
	return m
}

// devicesView — для окна: недавние устройства, новые сверху.
func devicesView() []map[string]any {
	arp := arpTable()
	devs.Lock()
	defer devs.Unlock()
	var list []*devInfo
	for ip, d := range devs.m {
		if time.Since(d.Last) > 24*time.Hour {
			delete(devs.m, ip)
			continue
		}
		if mac := arp[ip]; mac != "" {
			d.MAC = mac
		}
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Last.After(list[j].Last) })
	out := []map[string]any{}
	for _, d := range list {
		var via []string
		for _, v := range []string{"шлюз", "прокси", "Telegram", "DNS"} {
			if d.Via[v] {
				via = append(via, v)
			}
		}
		name := d.Name
		if name == "-" {
			name = ""
		}
		out = append(out, map[string]any{"ip": d.IP, "name": name, "mac": d.MAC, "via": strings.Join(via, ", "),
			"ago": int(time.Since(d.Last).Seconds()), "online": time.Since(d.Last) < 2*time.Minute,
			"bytes": d.bytes.Load(), "conns": d.Conns})
	}
	return out
}
