package version

import (
	"encoding/json"
	"fmt"
	"os"
)

// These variables are set via ldflags at build time.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// Print prints version information as JSON to stdout and exits.
func Print() {
	info := map[string]string{
		"version":   Version,
		"gitCommit": GitCommit,
		"buildDate": BuildDate,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(info); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode version info: %v\n", err)
		os.Exit(1)
	}
}
