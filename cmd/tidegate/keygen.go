package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// osExit is os.Exit, swappable in tests.
var osExit = os.Exit

// cmdKeygen generates a gateway client key. With --add NAME it appends the
// client to the gateway keyfile (default ~/.config/tidegate/clients.keys),
// creating it with 0600 permissions if needed. Without --add it prints the
// key to stdout for manual placement.
func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	add := fs.String("add", "", "Append the generated key to the keyfile as client NAME")
	keyfile := fs.String("keyfile", "", "Keyfile path (default: ~/.config/tidegate/clients.keys)")
	fs.Parse(args)

	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		osExit(1)
	}
	key := base64.RawURLEncoding.EncodeToString(buf)

	if *add == "" {
		fmt.Println(key)
		return
	}
	name := *add
	// Reject names that would corrupt the keyfile format: whitespace or
	// comment chars make the line unparseable by LoadKeyFile (review finding).
	if strings.ContainsAny(name, " 	#;") {
		fmt.Fprintf(os.Stderr, "Client name %q contains whitespace or comment characters\n", name)
		osExit(1)
		return
	}

	path := *keyfile
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".config", "tidegate", "clients.keys")
	}

	// Read existing clients so a duplicate name is an error, not a silent
	// second key (the first would keep working and confuse everyone).
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) == 2 && fields[0] == name {
				fmt.Fprintf(os.Stderr, "Client %q already exists in %s\n", name, path)
				osExit(1)
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config dir: %v\n", err)
		osExit(1)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening keyfile: %v\n", err)
		osExit(1)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s %s\n", name, key); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing keyfile: %v\n", err)
		osExit(1)
	}
	fmt.Printf("Client %q added to %s\n", name, path)
	fmt.Printf("Key: %s\n", key)
	fmt.Printf("Client config: X-Tidegate-Key header set to this value\n")
}
