package server

import (
	"log/slog"
	"net/http"
)

func logger(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f(w, r)
		slog.Info(r.URL.Path, "client", r.RemoteAddr)
	}
}
