package main

import (
	"strings"
	"unicode/utf8"
)

// Вывод консольных программ Windows (schtasks, netsh, sc) на русской системе — в кодировке
// CP866, а не UTF-8; без перекодировки сообщения об ошибках превращаются в «�����».
func decodeOEM(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c < 0x80:
			sb.WriteByte(c)
		case c <= 0xAF:
			sb.WriteRune([]rune("АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп")[c-0x80])
		case c >= 0xE0 && c <= 0xEF:
			sb.WriteRune([]rune("рстуфхцчшщъыьэюя")[c-0xE0])
		case c == 0xF0:
			sb.WriteRune('Ё')
		case c == 0xF1:
			sb.WriteRune('ё')
		case c == 0xFC:
			sb.WriteRune('№')
		default:
			sb.WriteRune(' ')
		}
	}
	return sb.String()
}
