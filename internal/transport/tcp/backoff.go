// Reconnection delay policy for the TCP transport. It is its own file because
// it must be testable WITHOUT opening a socket: a test asserts the delay
// sequence a fixed seed produces, which is only possible because the jitter
// comes from this transport's own explicitly seeded *rand.Rand - never from
// the package-global rand, whose source nobody in the test controls.
package tcp

import (
	"math/rand"
	"sync"
	"time"
)

// Backoff produces exponentially growing, jittered reconnection delays.
//
// One instance may be shared by every maintainer goroutine of a transport:
// Next is safe for concurrent use, and the shared rng is exactly what makes
// the delay sequence reproducible from the transport's one seed.
type Backoff struct {
	base time.Duration
	max  time.Duration
	rng  *rand.Rand
	mu   sync.Mutex // one rng drawn by many maintainer goroutines
}

// NewBackoff returns a Backoff doubling from base up to max, with jitter taken
// from rng. A nil rng means NO jitter - permitted only so a test can isolate
// the exponential curve; the transport always passes a seeded rng.
//
// base <= 0 disables the delay entirely (an immediate redial), which is the
// same thing max <= base does except before the first doubling: the clamp
// below makes every path land there rather than invent a minimum.
func NewBackoff(base, max time.Duration, rng *rand.Rand) *Backoff {
	return &Backoff{base: base, max: max, rng: rng}
}

// Next returns the delay before reconnection attempt n (1-based: attempt 1 is
// the first redial AFTER the connection was lost, not the initial dial).
//
// The uncontended delay doubles per attempt - base, 2*base, 4*base ... - and
// is clamped at max, so a peer that stays down cannot grow a delay without
// bound (nor overflow the arithmetic: the loop breaks the moment the clamp
// engages, no matter how large an attempt count arrives).
//
// The jitter is a uniform draw in [d/2, d): every delay remains BELOW twice
// the previous attempt's floor (2*(d/2) = d = next floor), so the sequence is
// strictly increasing for as long as the cap is not reached. That is the
// property the backoff test pins: growth is observable, not promised by the
// word "exponential".
func (b *Backoff) Next(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := b.base
	for i := 1; i < attempt; i++ {
		if d >= b.max {
			break
		}
		d *= 2
	}
	if d > b.max {
		d = b.max
	}
	half := d / 2
	if half <= 0 || b.rng == nil {
		return 0 // delay disabled, or no rng to jitter with
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	j := b.rng.Int63n(int64(half))
	return half + time.Duration(j)
}
