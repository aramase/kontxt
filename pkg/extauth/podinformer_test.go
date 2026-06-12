package extauth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func newPod(name, namespace, sa, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       corev1.PodSpec{ServiceAccountName: sa},
		Status:     corev1.PodStatus{PodIP: ip},
	}
}

func TestPodInformer_InitialSyncPopulatesResolver(t *testing.T) {
	// Pre-seed the API with a pod; once the informer's initial list
	// completes, ResolveFromPodIP should find it without any further events.
	client := fake.NewSimpleClientset(newPod("agent", "team-alpha", "my-agent", "10.0.0.42"))
	resolver := NewIdentityResolver()

	pi, err := NewPodInformer(client, resolver, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pi.Start(ctx)
	require.True(t, pi.WaitForCacheSync(ctx))
	assert.True(t, pi.HasSynced())

	id, err := resolver.ResolveFromPodIP("10.0.0.42")
	require.NoError(t, err)
	assert.Equal(t, "system:serviceaccount:team-alpha:my-agent", id.Subject)
}

func TestPodInformer_AddPropagates(t *testing.T) {
	client := fake.NewSimpleClientset()
	resolver := NewIdentityResolver()

	pi, err := NewPodInformer(client, resolver, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pi.Start(ctx)
	require.True(t, pi.WaitForCacheSync(ctx))

	_, err = client.CoreV1().Pods("team-alpha").Create(ctx, newPod("agent", "team-alpha", "my-agent", "10.0.0.42"), metav1.CreateOptions{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		_, err := resolver.ResolveFromPodIP("10.0.0.42")
		return err == nil
	}, time.Second, 10*time.Millisecond)
}

func TestPodInformer_DeletePropagates(t *testing.T) {
	pod := newPod("agent", "team-alpha", "my-agent", "10.0.0.42")
	client := fake.NewSimpleClientset(pod)
	resolver := NewIdentityResolver()

	pi, err := NewPodInformer(client, resolver, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pi.Start(ctx)
	require.True(t, pi.WaitForCacheSync(ctx))

	require.NoError(t, client.CoreV1().Pods("team-alpha").Delete(ctx, "agent", metav1.DeleteOptions{}))

	require.Eventually(t, func() bool {
		_, err := resolver.ResolveFromPodIP("10.0.0.42")
		return err != nil
	}, time.Second, 10*time.Millisecond)
}

func TestPodInformer_UpdatePropagates(t *testing.T) {
	pod := newPod("agent", "team-alpha", "my-agent", "10.0.0.42")
	client := fake.NewSimpleClientset(pod)
	resolver := NewIdentityResolver()

	pi, err := NewPodInformer(client, resolver, 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pi.Start(ctx)
	require.True(t, pi.WaitForCacheSync(ctx))

	// Mutate SA to confirm UpdatePod fires through the handler.
	updated := pod.DeepCopy()
	updated.Spec.ServiceAccountName = "rotated-agent"
	_, err = client.CoreV1().Pods("team-alpha").Update(ctx, updated, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		id, err := resolver.ResolveFromPodIP("10.0.0.42")
		return err == nil && id.ServiceAccount == "rotated-agent"
	}, time.Second, 10*time.Millisecond)
}

func TestPodInformer_OnDeleteTombstone(t *testing.T) {
	// Simulate a DeletedFinalStateUnknown tombstone (emitted when a watch is
	// lost and the informer relist detects the delete). The handler should
	// unwrap the embedded Pod and call resolver.DeletePod.
	resolver := NewIdentityResolver()
	resolver.UpdatePod(newPod("agent", "team-alpha", "my-agent", "10.0.0.42"))

	pi := &PodInformer{resolver: resolver}
	pi.onDelete(cache.DeletedFinalStateUnknown{
		Key: "team-alpha/agent",
		Obj: newPod("agent", "team-alpha", "my-agent", "10.0.0.42"),
	})

	_, err := resolver.ResolveFromPodIP("10.0.0.42")
	assert.Error(t, err)
}

func TestPodInformer_NilResolverRejected(t *testing.T) {
	_, err := NewPodInformer(fake.NewSimpleClientset(), nil, 0)
	require.Error(t, err)
}

func TestPodInformer_WaitForCacheSync_CancelledContext(t *testing.T) {
	// A cancelled context must cause WaitForCacheSync to return false rather
	// than hang the caller's startup.
	client := fake.NewSimpleClientset()
	pi, err := NewPodInformer(client, NewIdentityResolver(), 0)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	// Without Start, the informer never syncs; the cancelled ctx short-circuits.
	assert.False(t, pi.WaitForCacheSync(ctx))
}
