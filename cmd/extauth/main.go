package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aramase/kontxt/internal/version"
	"github.com/aramase/kontxt/pkg/extauth"
	"github.com/aramase/kontxt/pkg/extauth/ruleclient"
	sdktts "github.com/aramase/kontxt/sdk/tts"
	"github.com/aramase/kontxt/sdk/verify"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	addr := flag.String("addr", ":9000", "gRPC listen address")
	ttsEndpoint := flag.String("tts", "http://localhost:8080", "TTS endpoint")
	jwksURL := flag.String("jwks", "http://localhost:8080/.well-known/jwks.json", "TTS JWKS URL")
	trustDomain := flag.String("trust-domain", "trust-domain.example.com", "trust domain for TxToken verification")
	mode := flag.String("mode", "verify", "mode: verify or generate")
	controllerAddr := flag.String("controller-addr", "kontxt-controller.kontxt-system.svc.cluster.local:9090", "controller gRPC address for rule streaming")
	flag.Parse()

	if *showVersion {
		version.Print()
		os.Exit(0)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	gs := grpc.NewServer()

	rc := ruleclient.NewRuleClient(*controllerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch *mode {
	case "verify":
		verifier := verify.New(*jwksURL, *trustDomain)
		server := extauth.NewServer(verifier)
		rc.SetVerificationSetter(server)
		server.Register(gs)
		fmt.Printf("Ext auth adapter (verification mode) listening on %s\n", *addr)

	case "generate":
		ttsClient := sdktts.NewClient(*ttsEndpoint)
		resolver := extauth.NewIdentityResolver()
		server := extauth.NewGenerationServer(ttsClient, resolver)
		rc.SetGenerationSetter(server)
		extauth.RegisterGenerationServer(gs, server)
		fmt.Printf("Ext auth adapter (generation mode) listening on %s\n", *addr)

	default:
		log.Fatalf("Unknown mode: %s (use 'verify' or 'generate')", *mode)
	}

	go func() {
		if err := rc.Run(ctx); err != nil && err != context.Canceled {
			log.Printf("Rule client error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		gs.GracefulStop()
	}()

	if err := gs.Serve(lis); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}
