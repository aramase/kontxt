package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aramase/kontxt/internal/version"
	"github.com/aramase/kontxt/pkg/tts"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	configPath := flag.String("config", "config.yaml", "path to TTS configuration file")
	addr := flag.String("addr", ":8080", "address to listen on")
	flag.Parse()

	if *showVersion {
		version.Print()
		os.Exit(0)
	}

	cfg, err := tts.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	server, err := tts.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create TTS server: %v", err)
	}

	fmt.Printf("TTS server starting on %s\n", *addr)
	fmt.Printf("  Token endpoint: POST /token_endpoint\n")
	fmt.Printf("  JWKS endpoint:  GET /.well-known/jwks.json\n")
	fmt.Printf("  Health check:   GET /healthz\n")
	fmt.Printf("  Trust domain:   %s\n", cfg.TrustDomain)
	fmt.Printf("  Issuer:         %s\n", cfg.Issuer)

	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
