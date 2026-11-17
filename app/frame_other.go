//go:build !windows

package main

import "net/http"

func frameRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/win", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"custom":false}`))
	})
}
