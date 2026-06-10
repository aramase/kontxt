package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aramase/kontxt/internal/version"
	"github.com/aramase/kontxt/pkg/tts"
	"github.com/aramase/kontxt/pkg/tts/ruleclient"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	configPath := flag.String("config", "config.yaml", "path to TTS configuration file")
	addr := flag.String("addr", ":8080", "address to listen on")
	controllerAddr := flag.String("controller-addr", "", "controller gRPC address for issuance rule streaming (empty disables rule sync)")
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Optional: stream issuance rules from the controller and apply them to
	// the token handler. When --controller-addr is empty (e.g. local dev with
	// a standalone TTS), rule sync is disabled and the handler runs with the
	// empty rule set, which permits all issuance requests.
	var rc *ruleclient.RuleClient
	if *controllerAddr != "" {
		setter := ruleclient.NewHandlerSetter(server.TokenHandler())
		rc = ruleclient.NewRuleClient(*controllerAddr, setter,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		server.SetReadyCheck(func() error {
			if !rc.Ready() {
				return errors.New("issuance rules not yet synced")
			}
			return nil
		})
		go func() {
			if err := rc.Run(ctx); err != nil && err != context.Canceled {
				log.Printf("Rule client error: %v", err)
			}
		}()
	}

	fmt.Printf("TTS server starting on %s\n", *addr)
	fmt.Printf("  Token endpoint: POST /token_endpoint\n")
	fmt.Printf("  JWKS endpoint:  GET /.well-known/jwks.json\n")
	fmt.Printf("  Health check:   GET /healthz\n")
	fmt.Printf("  Readiness:      GET /readyz\n")
	fmt.Printf("  Trust domain:   %s\n", cfg.TrustDomain)
	fmt.Printf("  Issuer:         %s\n", cfg.Issuer)
	if *controllerAddr != "" {
		fmt.Printf("  Controller:     %s\n", *controllerAddr)
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
