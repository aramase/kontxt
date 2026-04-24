package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/aramase/kontxt/api/v1alpha1"
	rulesv1 "github.com/aramase/kontxt/gen/kontxt/rules/v1"
	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/internal/controller/ruleserver"
	"github.com/aramase/kontxt/internal/version"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	metricsAddr := flag.String("metrics-bind-address", ":8090", "metrics endpoint address")
	healthAddr := flag.String("health-probe-bind-address", ":8091", "health probe address")
	grpcAddr := flag.String("grpc-addr", ":9090", "gRPC address for rule distribution")
	flag.Parse()

	if *showVersion {
		version.Print()
		os.Exit(0)
	}

	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: *metricsAddr,
		},
		HealthProbeBindAddress: *healthAddr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to create manager: %v\n", err)
		os.Exit(1)
	}

	// Start gRPC rule distribution server.
	rs := ruleserver.NewRuleServer()
	gs := grpc.NewServer()
	rulesv1.RegisterRuleDiscoveryServiceServer(gs, rs)

	grpcLis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to listen on gRPC address %s: %v\n", *grpcAddr, err)
		os.Exit(1)
	}
	go func() {
		fmt.Printf("gRPC rule server listening on %s\n", *grpcAddr)
		if err := gs.Serve(grpcLis); err != nil {
			fmt.Fprintf(os.Stderr, "gRPC server failed: %v\n", err)
		}
	}()

	if err := (&controller.TransactionTypeReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		RulePublisher: rs,
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "unable to create TransactionType controller: %v\n", err)
		os.Exit(1)
	}

	if err := (&controller.ServiceTokenRequirementReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		RulePublisher: rs,
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "unable to create ServiceTokenRequirement controller: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Starting kontxt controller manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "controller manager exited with error: %v\n", err)
		os.Exit(1)
	}
	gs.GracefulStop()
}
