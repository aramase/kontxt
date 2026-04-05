package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	"github.com/aramase/kontxt/pkg/extauth"
	sdktts "github.com/aramase/kontxt/sdk/tts"
	"github.com/aramase/kontxt/sdk/verify"
)

func main() {
	addr := flag.String("addr", ":9000", "gRPC listen address")
	ttsEndpoint := flag.String("tts", "http://localhost:8080", "TTS endpoint")
	jwksURL := flag.String("jwks", "http://localhost:8080/.well-known/jwks.json", "TTS JWKS URL")
	trustDomain := flag.String("trust-domain", "trust-domain.example.com", "trust domain for TxToken verification")
	mode := flag.String("mode", "verify", "mode: verify or generate")
	rulesFile := flag.String("rules-file", "", "path to JSON rules file (from controller ConfigMap mount)")
	flag.Parse()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	gs := grpc.NewServer()

	var loader *extauth.RulesLoader
	if *rulesFile != "" {
		loader = extauth.NewRulesLoader(*rulesFile, *mode)
	}

	switch *mode {
	case "verify":
		verifier := verify.New(*jwksURL, *trustDomain)
		server := extauth.NewServer(verifier)
		if loader != nil {
			loader.SetVerifyServer(server)
			if err := loader.LoadOnce(); err != nil {
				log.Fatalf("Failed to load verification rules: %v", err)
			}
			done := make(chan struct{})
			go func() {
				if err := loader.WatchAndReload(done); err != nil {
					log.Printf("Rules watcher error: %v", err)
				}
			}()
		}
		server.Register(gs)
		fmt.Printf("Ext auth adapter (verification mode) listening on %s\n", *addr)

	case "generate":
		ttsClient := sdktts.NewClient(*ttsEndpoint)
		resolver := extauth.NewIdentityResolver()
		server := extauth.NewGenerationServer(ttsClient, resolver)
		if loader != nil {
			loader.SetGenerationServer(server)
			if err := loader.LoadOnce(); err != nil {
				log.Fatalf("Failed to load generation rules: %v", err)
			}
			done := make(chan struct{})
			go func() {
				if err := loader.WatchAndReload(done); err != nil {
					log.Printf("Rules watcher error: %v", err)
				}
			}()
		}
		extauth.RegisterGenerationServer(gs, server)
		fmt.Printf("Ext auth adapter (generation mode) listening on %s\n", *addr)

	default:
		log.Fatalf("Unknown mode: %s (use 'verify' or 'generate')", *mode)
	}

	if err := gs.Serve(lis); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}
