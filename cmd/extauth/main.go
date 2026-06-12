package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/aramase/kontxt/internal/version"
	"github.com/aramase/kontxt/pkg/extauth"
	"github.com/aramase/kontxt/pkg/extauth/ruleclient"
	sdktts "github.com/aramase/kontxt/sdk/tts"
	"github.com/aramase/kontxt/sdk/verify"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	addr := flag.String("addr", ":9000", "gRPC listen address")
	healthAddr := flag.String("health-addr", ":9090", "HTTP health endpoint listen address")
	ttsEndpoint := flag.String("tts", "http://localhost:8080", "TTS endpoint")
	jwksURL := flag.String("jwks", "http://localhost:8080/.well-known/jwks.json", "TTS JWKS URL")
	trustDomain := flag.String("trust-domain", "trust-domain.example.com", "trust domain for TxToken verification")
	mode := flag.String("mode", "verify", "mode: verify or generate")
	controllerAddr := flag.String("controller-addr", "kontxt-controller.kontxt-system.svc.cluster.local:9090", "controller gRPC address for rule streaming")
	enablePodInformer := flag.Bool("enable-pod-informer", true, "(generate mode only) watch Pods to resolve source IPs to workload identities; disable when running in Istio ambient mode where source.principal is always set")
	kubeconfig := flag.String("kubeconfig", "", "(generate mode only) path to a kubeconfig file for the pod informer; empty means in-cluster config")
	podResync := flag.Duration("pod-resync-period", 0, "(generate mode only) periodic resync interval for the pod informer; 0 disables periodic resync")
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

	// podInformer is non-nil in generate mode when --enable-pod-informer=true;
	// /readyz waits on its cache before reporting Ready.
	var podInformer *extauth.PodInformer

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

		if *enablePodInformer {
			cfg, err := loadKubeConfig(*kubeconfig)
			if err != nil {
				log.Fatalf("loading kube config for pod informer: %v", err)
			}
			cs, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				log.Fatalf("building kube client for pod informer: %v", err)
			}
			pi, err := extauth.NewPodInformer(cs, resolver, *podResync)
			if err != nil {
				log.Fatalf("creating pod informer: %v", err)
			}
			pi.Start(ctx)
			if !pi.WaitForCacheSync(ctx) {
				log.Fatalf("pod informer cache failed to sync before shutdown")
			}
			fmt.Println("Pod informer cache synced; pod-IP identity resolution enabled")
			podInformer = pi
		} else {
			fmt.Println("Pod informer disabled; relying on SPIFFE source.principal for identity resolution")
		}

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

	// Health endpoints:
	//   /healthz — always 200 once the process is up (liveness)
	//   /readyz  — 200 only after the rule client has received the initial
	//             snapshot from the controller and (in generate mode) the
	//             pod informer cache has synced
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	healthMux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !rc.Ready() {
			http.Error(w, "rules not yet synced", http.StatusServiceUnavailable)
			return
		}
		if podInformer != nil && !podInformer.HasSynced() {
			http.Error(w, "pod informer not yet synced", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	healthSrv := &http.Server{
		Addr:              *healthAddr,
		Handler:           healthMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		fmt.Printf("Health endpoints listening on %s\n", *healthAddr)
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Health server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = healthSrv.Shutdown(shutdownCtx)
		gs.GracefulStop()
	}()

	if err := gs.Serve(lis); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}

// loadKubeConfig returns an in-cluster rest.Config when kubeconfigPath is
// empty, otherwise loads the kubeconfig from disk. Used by the pod informer
// in generate mode.
func loadKubeConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath == "" {
		return rest.InClusterConfig()
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
}
