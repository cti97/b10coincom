package chain

// Audit R-2 (2026-11-01): BlockAt must not hold the chain's read lock across
// the store's disk read and the decode, because every reader already inside
// a serialised read then delays Append. Releasing the lock is only safe if the
// store's own index is guarded on its own, which is what this test, run under
// the race detector, pins: historical reads and appends in parallel, with
// every read answered.

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
)

func TestBlockAtRunsConcurrentlyWithAppendWithoutARace(t *testing.T) {
	c, err := Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()
	grow := func(n int) {
		for i := 0; i < n; i++ {
			b, err := c.Build(priv, nil, c.Head().Header.Timestamp+1)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Append(b); err != nil {
				t.Fatal(err)
			}
		}
	}
	grow(8) // heights 1..8 are on disk, below the head

	const readers = 4
	var wg sync.WaitGroup
	errs := make(chan error, readers)
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 50; round++ {
				for h := uint64(1); h <= 8; h++ {
					b, err := c.BlockAt(h)
					if err != nil {
						errs <- err
						return
					}
					if b.Header.Height != h {
						errs <- errHeight{h, b.Header.Height}
						return
					}
				}
			}
		}()
	}
	grow(40) // appends land while the readers run
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

type errHeight [2]uint64

func (e errHeight) Error() string {
	return fmt.Sprintf("BlockAt(%d) returned the block at height %d", e[0], e[1])
}
