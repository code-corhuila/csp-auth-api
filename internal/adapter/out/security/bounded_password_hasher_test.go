package security

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// blockingHasher is an out.PasswordHasher whose calls wait until release is closed, like a bcrypt that is busy.
type blockingHasher struct {
	mu      sync.Mutex
	running int
	started chan struct{}
	release chan struct{}
}

func newBlockingHasher() *blockingHasher {
	return &blockingHasher{started: make(chan struct{}, 16), release: make(chan struct{})}
}

func (h *blockingHasher) enter() {
	h.mu.Lock()
	h.running++
	h.mu.Unlock()
	h.started <- struct{}{}
	<-h.release
	h.mu.Lock()
	h.running--
	h.mu.Unlock()
}

func (h *blockingHasher) Hash(model.Password) (string, error) {
	h.enter()
	return "hash", nil
}

func (h *blockingHasher) Verify(string, string) (bool, error) {
	h.enter()
	return true, nil
}

func (h *blockingHasher) inFlight() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.running
}

func fillTheSlots(t *testing.T, bounded *BoundedPasswordHasher, inner *blockingHasher, slots int) *sync.WaitGroup {
	t.Helper()
	var running sync.WaitGroup
	for range slots {
		running.Add(1)
		go func() {
			defer running.Done()
			_, _ = bounded.Verify("hash", "secret")
		}()
		<-inner.started
	}
	return &running
}

func TestTheHashAfterTheLastFreeSlotIsRefusedBeforeTheQueueTimeoutPlusMargin(t *testing.T) {
	inner := newBlockingHasher()
	bounded := NewBoundedPasswordHasher(inner, 2, 50*time.Millisecond)
	running := fillTheSlots(t, bounded, inner, 2)
	defer func() { close(inner.release); running.Wait() }()
	started := time.Now()

	_, err := bounded.Hash(mustPassword(t, "Secret123"))

	if !errors.Is(err, model.ErrPasswordHasherBusy) {
		t.Fatalf("Hash() error = %v, want ErrPasswordHasherBusy", err)
	}
	if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
		t.Errorf("the refusal took %v, want less than 200ms", elapsed)
	}
	if inner.inFlight() != 2 {
		t.Errorf("in flight = %d, want 2: a refused call must not reach bcrypt", inner.inFlight())
	}
}

func TestAVerificationIsRefusedLikeAHashWhenTheSlotsAreTaken(t *testing.T) {
	inner := newBlockingHasher()
	bounded := NewBoundedPasswordHasher(inner, 1, 20*time.Millisecond)
	running := fillTheSlots(t, bounded, inner, 1)
	defer func() { close(inner.release); running.Wait() }()

	ok, err := bounded.Verify("hash", "secret")

	if ok || !errors.Is(err, model.ErrPasswordHasherBusy) {
		t.Errorf("Verify() = %v, %v; want false and ErrPasswordHasherBusy", ok, err)
	}
}

func TestACallThatWaitsLessThanTheQueueTimeoutGetsTheSlotThatIsFreed(t *testing.T) {
	inner := newBlockingHasher()
	bounded := NewBoundedPasswordHasher(inner, 1, 500*time.Millisecond)
	running := fillTheSlots(t, bounded, inner, 1)
	result := make(chan error, 1)
	go func() {
		_, err := bounded.Verify("hash", "secret")
		result <- err
	}()
	time.Sleep(50 * time.Millisecond)

	close(inner.release)
	running.Wait()

	select {
	case err := <-result:
		if err != nil {
			t.Errorf("the queued call got %v, want it to run once the slot was freed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("the queued call never finished")
	}
}

func TestEverySlotIsGivenBackSoTheBoundIsNotLeaked(t *testing.T) {
	inner := newBlockingHasher()
	close(inner.release)
	bounded := NewBoundedPasswordHasher(inner, 1, 10*time.Millisecond)

	for i := range 5 {
		if _, err := bounded.Verify("hash", "secret"); err != nil {
			t.Fatalf("call %d: error = %v, want every sequential call to find the slot free", i+1, err)
		}
		<-inner.started
	}
}

func TestTheBoundedHasherKeepsTheResultOfTheRealOne(t *testing.T) {
	bounded := NewBoundedPasswordHasher(NewBcryptHasher(4), 2, 50*time.Millisecond)

	hash, err := bounded.Hash(mustPassword(t, "Secret123"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if ok, err := bounded.Verify(hash, "Secret123"); !ok || err != nil {
		t.Errorf("Verify(right) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := bounded.Verify(hash, "secret123"); ok || err != nil {
		t.Errorf("Verify(wrong) = %v, %v; want false, nil: a wrong password is not an error", ok, err)
	}
}
