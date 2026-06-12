package extauth

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PodInformer keeps an IdentityResolver populated with the cluster's pods so
// that ResolveFromPodIP can map a source IP to a workload identity. It is the
// adapter the ext-auth "generate" mode uses when no SPIFFE principal is
// present on the request (typical of standalone, non-ambient deployments).
//
// In Istio ambient mode the source.principal is always set and is preferred
// over pod IP resolution; in that case the informer can be skipped entirely.
type PodInformer struct {
	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer
	resolver *IdentityResolver
}

// NewPodInformer wires a core/v1 Pod informer to the given resolver. The
// resyncPeriod controls the periodic cache resync; pass 0 to disable resync
// and rely purely on watch events.
func NewPodInformer(client kubernetes.Interface, resolver *IdentityResolver, resyncPeriod time.Duration) (*PodInformer, error) {
	if resolver == nil {
		return nil, fmt.Errorf("nil resolver")
	}
	factory := informers.NewSharedInformerFactory(client, resyncPeriod)
	pi := &PodInformer{
		factory:  factory,
		informer: factory.Core().V1().Pods().Informer(),
		resolver: resolver,
	}
	if _, err := pi.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    pi.onAdd,
		UpdateFunc: pi.onUpdate,
		DeleteFunc: pi.onDelete,
	}); err != nil {
		return nil, fmt.Errorf("registering pod event handler: %w", err)
	}
	return pi, nil
}

// Start begins informer execution. It returns immediately; the underlying
// factory's goroutines stop when ctx is cancelled.
func (p *PodInformer) Start(ctx context.Context) {
	p.factory.Start(ctx.Done())
}

// WaitForCacheSync blocks until the initial list has populated the resolver
// or ctx is cancelled. Returns true on success, false if ctx was cancelled
// or the informer stopped early.
func (p *PodInformer) WaitForCacheSync(ctx context.Context) bool {
	return cache.WaitForCacheSync(ctx.Done(), p.informer.HasSynced)
}

// HasSynced reports whether the initial list has completed. Use this in
// readiness probes so the ext-auth adapter doesn't accept traffic before
// pod-IP lookups can succeed.
func (p *PodInformer) HasSynced() bool {
	return p.informer.HasSynced()
}

func (p *PodInformer) onAdd(obj any) {
	if pod, ok := obj.(*corev1.Pod); ok {
		p.resolver.UpdatePod(pod)
	}
}

func (p *PodInformer) onUpdate(_, newObj any) {
	if pod, ok := newObj.(*corev1.Pod); ok {
		p.resolver.UpdatePod(pod)
	}
}

// onDelete handles both normal deletes (*corev1.Pod) and the
// DeletedFinalStateUnknown tombstone the informer emits when a watch is
// lost and a delete is detected only after relist.
func (p *PodInformer) onDelete(obj any) {
	switch o := obj.(type) {
	case *corev1.Pod:
		p.resolver.DeletePod(o)
	case cache.DeletedFinalStateUnknown:
		if pod, ok := o.Obj.(*corev1.Pod); ok {
			p.resolver.DeletePod(pod)
		}
	}
}
