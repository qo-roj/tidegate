package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/qo-roj/tidegate/internal/wrap"
)

func cmdWrap(args []string) {
	fs := flag.NewFlagSet("wrap", flag.ExitOnError)
	baseURL := fs.String("base-url", "", "Gateway base URL (default: http://127.0.0.1:<port>/<provider>/v1)")
	key := fs.String("key", "", "Gateway client key (X-Tidegate-Key), for gateway mode")
	port := fs.Int("port", 8842, "Gateway port used to build the default base URL")
	list := fs.Bool("list", false, "List supported agents")
	fs.Parse(args)

	if *list || fs.NArg() == 0 {
		fmt.Println("Supported agents:")
		for _, a := range wrap.Agents() {
			fmt.Printf("  %-9s %s\n", a, wrap.DefaultBaseURL(a, *port))
		}
		fmt.Println("\nUsage: tidegate wrap <agent> [--base-url URL] [--key KEY]")
		return
	}

	agent := fs.Arg(0)
	base := *baseURL
	if base == "" {
		base = wrap.DefaultBaseURL(agent, *port)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving home directory: %v\n", err)
		os.Exit(1)
	}

	res, err := wrap.Apply(agent, base, *key, home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error wrapping %s: %v\n", agent, err)
		os.Exit(1)
	}

	if agent == "env" {
		fmt.Println("# Add to your shell profile, or eval the output:")
		for _, line := range res.Exports {
			fmt.Println(line)
		}
		return
	}

	verb := "Updated"
	if res.Created {
		verb = "Created"
	}
	fmt.Printf("🦞 %s %s\n   base_url: %s\n", verb, res.ConfigPath, base)
	if *key != "" {
		fmt.Println("   client key: set (file mode 0600)")
	} else {
		fmt.Println("   client key: none (single-machine mode)")
	}
	fmt.Printf("\nUndo with: tidegate unwrap %s\n", agent)
}

func cmdUnwrap(args []string) {
	fs := flag.NewFlagSet("unwrap", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: tidegate unwrap <agent>")
		os.Exit(1)
	}
	agent := fs.Arg(0)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving home directory: %v\n", err)
		os.Exit(1)
	}

	res, err := wrap.Remove(agent, home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error unwrapping %s: %v\n", agent, err)
		os.Exit(1)
	}
	if res.ConfigPath != "" {
		fmt.Printf("🦞 Restored %s\n", res.ConfigPath)
	} else {
		fmt.Printf("🦞 %s needed no file changes\n", agent)
	}
}
