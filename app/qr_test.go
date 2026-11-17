package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"
)

func TestQRWrite(t *testing.T) {
	texts := []string{"http://192.168.137.1:10830/proxy.pac", "WIFI:T:WPA;S:DISP-Hotspot;P:k3y-p4ss;;", "Привет, мир! " + string(make([]byte, 0)), "WIFI:T:WPA;S:Моя сеть 5G;P:очень-длинный-пароль-12345;;http://192.168.1.42:10830/proxy.pac/abcdefghijklmnopqrstuvwxyz0123456789"}
	for i, s := range texts {
		q, err := qrEncode(s)
		if err != nil {
			t.Fatal(err)
		}
		sc := 8
		n := (q.size + 8) * sc
		img := image.NewGray(image.Rect(0, 0, n, n))
		for y := 0; y < n; y++ {
			for x := 0; x < n; x++ {
				mx, my := x/sc-4, y/sc-4
				c := color.Gray{255}
				if mx >= 0 && my >= 0 && mx < q.size && my < q.size && q.mod[my][mx] {
					c = color.Gray{0}
				}
				img.SetGray(x, y, c)
			}
		}
		f, _ := os.Create(fmt.Sprintf("/tmp/qr%d.png", i))
		png.Encode(f, img)
		f.Close()
		os.WriteFile(fmt.Sprintf("/tmp/qr%d.txt", i), []byte(s), 0644)
		t.Logf("v%d", q.ver)
	}
}
