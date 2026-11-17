package main

// Минимальный генератор QR-кодов (байтовый режим, уровень коррекции M, версии 1–40)
// по стандарту ISO/IEC 18004. Выдаёт SVG — для QR в окне раздачи.

import (
	"errors"
	"fmt"
	"strings"
)

var qrEccPerBlockM = [41]int{-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28}
var qrNumBlocksM = [41]int{-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49}

type qrCode struct {
	ver, size int
	mod, fn   [][]bool
}

func qrRawModules(ver int) int {
	r := (16*ver+128)*ver + 64
	if ver >= 2 {
		na := ver/7 + 2
		r -= (25*na-10)*na - 55
		if ver >= 7 {
			r -= 36
		}
	}
	return r
}

func qrDataCodewords(ver int) int {
	return qrRawModules(ver)/8 - qrEccPerBlockM[ver]*qrNumBlocksM[ver]
}

func gfMul(x, y byte) byte {
	var z int
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ ((z >> 7) * 0x11D)
		z ^= int((y>>uint(i))&1) * int(x)
	}
	return byte(z)
}

func rsDivisor(deg int) []byte {
	r := make([]byte, deg)
	r[deg-1] = 1
	root := byte(1)
	for i := 0; i < deg; i++ {
		for j := range r {
			r[j] = gfMul(r[j], root)
			if j+1 < len(r) {
				r[j] ^= r[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return r
}

func rsRemainder(data, div []byte) []byte {
	r := make([]byte, len(div))
	for _, b := range data {
		f := b ^ r[0]
		copy(r, r[1:])
		r[len(r)-1] = 0
		for i, c := range div {
			r[i] ^= gfMul(c, f)
		}
	}
	return r
}

func qrEncode(text string) (*qrCode, error) {
	data := []byte(text)
	ver := 0
	for v := 1; v <= 40; v++ {
		cc := 8
		if v > 9 {
			cc = 16
		}
		if 4+cc+8*len(data) <= qrDataCodewords(v)*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("слишком длинный текст для QR")
	}
	// биты: режим 0100, длина, данные
	var bits []bool
	put := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (v>>uint(i))&1 == 1)
		}
	}
	put(4, 4)
	if ver > 9 {
		put(len(data), 16)
	} else {
		put(len(data), 8)
	}
	for _, b := range data {
		put(int(b), 8)
	}
	capBits := qrDataCodewords(ver) * 8
	t := capBits - len(bits)
	if t > 4 {
		t = 4
	}
	put(0, t)
	put(0, (8-len(bits)%8)%8)
	for pad := 0xEC; len(bits) < capBits; pad ^= 0xEC ^ 0x11 {
		put(pad, 8)
	}
	cw := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			cw[i>>3] |= 1 << uint(7-i&7)
		}
	}
	// коррекция ошибок и перемешивание блоков
	nb, eccLen := qrNumBlocksM[ver], qrEccPerBlockM[ver]
	raw := qrRawModules(ver) / 8
	nShort := nb - raw%nb
	shortLen := raw / nb
	div := rsDivisor(eccLen)
	var blocks [][]byte
	k := 0
	for i := 0; i < nb; i++ {
		l := shortLen - eccLen
		if i >= nShort {
			l++
		}
		dat := append([]byte{}, cw[k:k+l]...)
		k += l
		ecc := rsRemainder(dat, div)
		if i < nShort {
			dat = append(dat, 0)
		}
		blocks = append(blocks, append(dat, ecc...))
	}
	var final []byte
	for i := range blocks[0] {
		for j, b := range blocks {
			if i != shortLen-eccLen || j >= nShort {
				final = append(final, b[i])
			}
		}
	}

	q := &qrCode{ver: ver, size: ver*4 + 17}
	q.mod = make([][]bool, q.size)
	q.fn = make([][]bool, q.size)
	for i := range q.mod {
		q.mod[i] = make([]bool, q.size)
		q.fn[i] = make([]bool, q.size)
	}
	q.drawFunctions()
	q.drawCodewords(final)
	best, bestP := 0, -1
	for m := 0; m < 8; m++ {
		q.applyMask(m)
		q.drawFormat(m)
		if p := q.penalty(); bestP < 0 || p < bestP {
			best, bestP = m, p
		}
		q.applyMask(m)
	}
	q.applyMask(best)
	q.drawFormat(best)
	return q, nil
}

func (q *qrCode) set(x, y int, dark bool) { q.mod[y][x] = dark; q.fn[y][x] = true }

func (q *qrCode) drawFunctions() {
	for i := 0; i < q.size; i++ {
		q.set(6, i, i%2 == 0)
		q.set(i, 6, i%2 == 0)
	}
	finder := func(x, y int) {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				xx, yy := x+dx, y+dy
				if xx < 0 || yy < 0 || xx >= q.size || yy >= q.size {
					continue
				}
				d := abs(dx)
				if abs(dy) > d {
					d = abs(dy)
				}
				q.set(xx, yy, d != 2 && d != 4)
			}
		}
	}
	finder(3, 3)
	finder(q.size-4, 3)
	finder(3, q.size-4)
	pos := q.alignPositions()
	n := len(pos)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					d := abs(dx)
					if abs(dy) > d {
						d = abs(dy)
					}
					q.set(pos[i]+dx, pos[j]+dy, d != 1)
				}
			}
		}
	}
	q.drawFormat(0)
	if q.ver >= 7 {
		rem := q.ver
		for i := 0; i < 12; i++ {
			rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
		}
		b := q.ver<<12 | rem
		for i := 0; i < 18; i++ {
			bit := (b>>uint(i))&1 == 1
			a, c := q.size-11+i%3, i/3
			q.set(a, c, bit)
			q.set(c, a, bit)
		}
	}
}

func (q *qrCode) alignPositions() []int {
	if q.ver == 1 {
		return nil
	}
	na := q.ver/7 + 2
	step := (q.ver*8 + na*3 + 5) / (na*4 - 4) * 2
	res := make([]int, na)
	res[0] = 6
	for i, pos := na-1, q.size-7; i >= 1; i, pos = i-1, pos-step {
		res[i] = pos
	}
	return res
}

func (q *qrCode) drawFormat(mask int) {
	data := 0<<3 | mask // уровень M = 00
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	b := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return (b>>uint(i))&1 == 1 }
	for i := 0; i <= 5; i++ {
		q.set(8, i, bit(i))
	}
	q.set(8, 7, bit(6))
	q.set(8, 8, bit(7))
	q.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		q.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		q.set(q.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		q.set(8, q.size-15+i, bit(i))
	}
	q.set(8, q.size-8, true)
}

func (q *qrCode) drawCodewords(data []byte) {
	i := 0
	for right := q.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for v := 0; v < q.size; v++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := v
				if (right+1)&2 == 0 {
					y = q.size - 1 - v
				}
				if !q.fn[y][x] && i < len(data)*8 {
					q.mod[y][x] = (data[i>>3]>>uint(7-i&7))&1 == 1
					i++
				}
			}
		}
	}
}

func (q *qrCode) applyMask(m int) {
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			var inv bool
			switch m {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if inv && !q.fn[y][x] {
				q.mod[y][x] = !q.mod[y][x]
			}
		}
	}
}

// Упрощённый штраф: серии, блоки 2×2 и баланс тёмных модулей.
func (q *qrCode) penalty() int {
	p, dark := 0, 0
	for y := 0; y < q.size; y++ {
		for _, horiz := range []bool{true, false} {
			run := 0
			var last bool
			for x := 0; x < q.size; x++ {
				c := q.mod[y][x]
				if !horiz {
					c = q.mod[x][y]
				}
				if x > 0 && c == last {
					run++
					if run == 5 {
						p += 3
					} else if run > 5 {
						p++
					}
				} else {
					run, last = 1, c
				}
			}
		}
		for x := 0; x < q.size; x++ {
			if q.mod[y][x] {
				dark++
			}
			if x+1 < q.size && y+1 < q.size {
				c := q.mod[y][x]
				if c == q.mod[y][x+1] && c == q.mod[y+1][x] && c == q.mod[y+1][x+1] {
					p += 3
				}
			}
		}
	}
	total := q.size * q.size
	k := (abs(dark*20-total*10) + total - 1) / total
	return p + (k-1)*10
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func qrSVG(text string) (string, error) {
	q, err := qrEncode(text)
	if err != nil {
		return "", err
	}
	n := q.size + 8
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			if q.mod[y][x] {
				fmt.Fprintf(&sb, "M%d,%dh1v1h-1z", x+4, y+4)
			}
		}
	}
	sb.WriteString(`"/></svg>`)
	return sb.String(), nil
}
