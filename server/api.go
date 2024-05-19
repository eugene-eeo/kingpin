package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"local/kingpin/keypair"
	"local/kingpin/token"
)

const (
	maxBodyBytes = 1024
)

type Server struct {
	ca       *keypair.KeyPair
	key      []byte
	caPubKey []byte
	username string
	password string
}

func (s *Server) authenticate(username, password string) bool {
	return subtle.ConstantTimeCompare([]byte(username), []byte(s.username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(password)) == 1
}

func (s *Server) generateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok || !s.authenticate(username, password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	var csr keypair.Request
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)

	if err := dec.Decode(&csr); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	if err := csr.Validate(); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	tok, err := token.NewToken(csr.Encode(), s.key)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"token":"%s"}`, tok)))
	w.Write([]byte("\n"))
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	var csr keypair.Request
	csrData, err := token.Parse(r.Header.Get("X-Token"), s.key)
	if err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	if err := json.Unmarshal(csrData, &csr); err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}

	if err := csr.Validate(); err != nil {
		http.Error(w, fmt.Sprintf("invalid csr: %s", err), http.StatusBadRequest)
		return
	}

	pk, err := keypair.ParsePubKey(buf)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid pubkey: %s", err), http.StatusBadRequest)
		return
	}

	sig, err := keypair.Sign(&csr, s.ca, pk)
	if err != nil {
		slog.Error("keypair.Sign failed", "pk", string(buf), "err", err)
		http.Error(w, fmt.Sprintf("internal server error: %s", err), http.StatusInternalServerError)
		return
	}
	w.Write(sig)
}

func (s *Server) serveCa(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	w.Write(s.caPubKey)
}

func (s *Server) server() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/ca/{$}", logger(s.serveCa))
	mux.HandleFunc("/token/{$}", logger(s.generateToken))
	mux.HandleFunc("/sign/{$}", logger(s.sign))
	return mux
}

func (s *Server) ListenAndServe(addrs []string) {
	slog.Info("listening on", "addrs", addrs)
	exitChan := make(chan error)
	mux := s.server()
	for _, addr := range addrs {
		go func(addr string) {
			exitChan <- http.ListenAndServe(addr, mux)
		}(addr)
	}
	<-exitChan
}

func NewServer(ca *keypair.KeyPair, key []byte, username, password string) (*Server, error) {
	return &Server{
		ca:       ca,
		caPubKey: append(ca.PublicKey(), '\n'),
		key:      key,
		username: username,
		password: password,
	}, nil
}
