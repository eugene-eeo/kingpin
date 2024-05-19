package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"

	"local/kingpin/keypair"
	"local/kingpin/server"
)

func GetInterfaceAddr(name string, port int) ([]string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %q: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("cannot list interface %q addresses: %w", iface.Name, err)
	}
	all := []string{}
	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if ok && !(ip.IP.IsLinkLocalMulticast() || ip.IP.IsLinkLocalUnicast()) {
			all = append(all, fmt.Sprintf("%s:%d", ip.IP.String(), port))
		}
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no suitable addresses found")
	}
	return all, nil
}

func main() {
	ifname := flag.String("ifname", "", "interface to listen on")
	addr := flag.String("addr", "", "address to listen on")
	port := flag.Int("port", 2222, "port to listen on")
	secret := flag.String("secret", "secret", "secret for token generation")
	username := flag.String("username", "admin", "username for token generation")
	password := flag.String("password", "admin", "password for token generation")
	caPath := flag.String("ca", "", "path to CA secret key")
	flag.Parse()

	if *addr == "" && *ifname == "" {
		slog.Error("one of addr and ifname must be specified.")
		os.Exit(1)
	}

	if *caPath == "" {
		slog.Error("CA path must be specified.")
		os.Exit(1)
	}

	addrs := []string{fmt.Sprintf("%s:%d", *addr, *port)}
	if *ifname != "" {
		var err error
		addrs, err = GetInterfaceAddr(*ifname, *port)
		if err != nil {
			slog.Error("failed to get interface address", "err", err)
			os.Exit(1)
		}
	}

	ca, err := keypair.ParseKeyFile(*caPath)
	if err != nil {
		slog.Error("failed to parse key file", "err", err)
		os.Exit(1)
	}

	srv, err := server.NewServer(ca, []byte(*secret), *username, *password)
	if err != nil {
		slog.Error("failed to initialize server", "err", err)
		os.Exit(1)
	}
	srv.ListenAndServe(addrs)
}
