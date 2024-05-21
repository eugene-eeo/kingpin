package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	extensionSuffix = "@no.cloud"
	machineKey      = "machine" + extensionSuffix
)

var labelSetRegex = regexp.MustCompile(`^labels(\-\d+){0,1}` + regexp.QuoteMeta(extensionSuffix) + `$`)

type MachineConfiguration struct {
	Machine       string            `json:"machine"` // Name of the machine, i.e. hostname
	Labels        map[string]string `json:"labels"`
	AllowedLogins []string          `json:"allowed_logins"` // Allowed list of logins.
}

func die(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

func readConfiguration(path string) *MachineConfiguration {
	var mcfg MachineConfiguration
	b, err := os.ReadFile(path)
	if err != nil {
		die("error reading configuration", "err", err)
	}
	if err := json.Unmarshal(b, &mcfg); err != nil {
		die("error parsing configuration", "err", err)
	}
	return &mcfg
}

func matchMachineName(extensions map[string]string, cfg *MachineConfiguration) bool {
	machineNamesStr, ok := extensions[machineKey]
	if !ok {
		return false
	}
	if machineNamesStr == "*" {
		return true
	}
	machineNames := strings.Split(machineNamesStr, ",")
	return slices.Contains(machineNames, cfg.Machine)
}

// parses a comma-separated label list into a map
func parseLabelSet(s string) map[string]string {
	labels := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(part, "=", 2)
		v := kv[1]
		if len(kv) == 2 {
			v = kv[1]
		}
		labels[kv[0]] = v
	}
	return labels
}

func matchLabels(extensions map[string]string, cfg *MachineConfiguration) bool {
	// this means, if we get:
	//   labels-0@no.cloud: k1=v1,k2=v2
	//   labels-1@no.cloud: k3=v3
	// _either_ one of those must fully match.
	for extKey, extValue := range extensions {
		if !labelSetRegex.MatchString(extKey) {
			continue
		}
		match := true
		for k, v := range parseLabelSet(extValue) {
			if v == "" {
				if _, ok := cfg.Labels[k]; !ok {
					match = false
					break
				}
			} else if cfg.Labels[k] != v {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func verifyCert(cert *ssh.Certificate, cfg *MachineConfiguration) bool {
	return matchMachineName(cert.Extensions, cfg) ||
		matchLabels(cert.Extensions, cfg)
}

func filterPrincipals(cert *ssh.Certificate, cfg *MachineConfiguration) []string {
	// don't return anything if the user doesn't configure cfg.AllowedLogins
	if len(cfg.AllowedLogins) == 0 {
		return nil
	}
	if len(cfg.AllowedLogins) == 1 && cfg.AllowedLogins[0] == ":any" {
		return cert.ValidPrincipals
	}
	filtered := []string{}
	for _, p := range cert.ValidPrincipals {
		if slices.Contains(cfg.AllowedLogins, p) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func main() {
	b64Cert := flag.String("base64-cert", "", "base64-encoded SSH user certificate")
	config := flag.String("config", "/etc/no.cloud/machine.json", "path to machine configuration")
	flag.Parse()

	if *b64Cert == "" {
		slog.Error("no base64-cert specified")
		os.Exit(1)
	}

	machineConfig := readConfiguration(*config)

	certBytes, err := base64.StdEncoding.DecodeString(*b64Cert)
	if err != nil {
		slog.Error("invalid base64-cert specified", "err", err)
		os.Exit(1)
	}

	pk, err := ssh.ParsePublicKey(certBytes)
	if err != nil {
		slog.Error("error parsing certificate", "err", err)
		os.Exit(1)
	}

	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		slog.Error("error parsing certificate", "err", err)
		os.Exit(1)
	}

	if verifyCert(cert, machineConfig) {
		for _, p := range filterPrincipals(cert, machineConfig) {
			fmt.Println(p)
		}
	}
}
