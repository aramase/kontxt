package main

import (
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/aramase/kontxt/api/v1alpha1"
	"github.com/aramase/kontxt/internal/controller"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	metricsAddr := flag.String("metrics-bind-address", ":8090", "metrics endpoint address")
	healthAddr := flag.String("health-probe-bind-address", ":8091", "health probe address")
	flag.Parse()

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

	if err := (&controller.TransactionTypeReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "unable to create TransactionType controller: %v\n", err)
		os.Exit(1)
	}

	if err := (&controller.ServiceTokenRequirementReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "unable to create ServiceTokenRequirement controller: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Starting kontxt controller manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "controller manager exited with error: %v\n", err)
		os.Exit(1)
	}
}
