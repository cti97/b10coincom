package devnet

// RT-3's acceptance evidence: a validator that JOINED AFTER GENESIS, was
// seated, and then ROTATED OUT is not frozen. This is the case `4972883`
// recorded as open when it landed RT-1: sync and HELLO authorisation were
// genesis U committee-at-the-request-height U committee-at-head, so once peers
// moved past the epochs that held the key it was in none of them. Its engine
// is inert by design (it emits nothing), its catch-up pull was refused, and
// the live process could never follow the chain again; only its funds were
// recoverable, through another node's RPC.
//
// The test constructs the whole state, nothing by timing:
//
//  1. five genesis seats of a SIX-seat committee, and two funded non-genesis
//     keys: J (the joiner) and K (the evictor);
//  2. J bonds and epoch 1 seats it; J starts a node on a chain REPLAYED from a
//     donor's committed blocks and its precommit is counted by the committee
//     that was already running (RT-1's proof, reused as the setup);
//  3. K bonds twice MIN_STAKE, so epoch 2's top-six seats are the five genesis
//     keys plus K - J is rotated OUT, while its node stays up (a restart would
//     be refused by the entry check, which is RT-1's rule and deliberately
//     unchanged);
//  4. J's chain must keep following the committee PAST the boundary even
//     though it is seated nowhere: every pull whose asker head is in epoch 2
//     is authorised only by "has ever held a seat", and every HELLO it
//     announces from epoch 2 is admitted by that same term. Both are asserted
//     against positive observables (a height adopted, a peer's attested
//     height);
//  5. K unbonds fully in epoch 2, so epoch 3 re-seats J. J's driver, which had
//     halted at the unseated boundary, is rebuilt on the next adopted block,
//     votes, and its precommit appears in a quorum-reaching certificate again
//     - "counted again" is the certificate's arithmetic, not a height that
//     moved.
//
// The boundary is asserted on the SAME chain and the SAME head: a key that
// never held a seat is still refused by committeeMemberAt (the HELLO gate) and
// has no ever-seated record, so the widening is "ever seated", not "any key".

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/types"
)

const (
	// rt3Seats and rt3Committee: five genesis seats and ONE spare seat. The
	// six-seat committee keeps a quorum of five, so five live genesis seats
	// can cross the two boundaries without the joining or evicting node - the
	// test never rests on an absent seat's vote for liveness.
	rt3Seats     = 5
	rt3Committee = 6
	// rt3Epoch is a short epoch: enough heights to observe each state, few
	// enough that the test crosses three boundaries in seconds.
	rt3Epoch = uint64(10)
	// The fixture cadence, as in the rotation-in test: slow enough that a
	// catching-up node participates rather than chasing a 50 ms block time.
	rt3Tick = 150 * time.Millisecond
	rt3Wave = 100 * time.Millisecond
)

// rt3Genesis is five genesis seats at TWICE MIN_STAKE, a six-seat committee,
// and two funded non-genesis accounts: the joiner (enough for one MIN_STAKE
// bond and its fee) and the evictor (enough for three times MIN_STAKE and its
// fee). The unequal stakes matter: with every candidate at the same amount the
// seat boundary would run through the key-byte tie-break (audit RT-8), and
// whether the joiner or a genesis seat fell out would depend on key ordering.
// Here the evictor is strictly heavier than every genesis seat and the joiner
// strictly lighter, so the rotation out is a stake ordering, not a tie.
func rt3Genesis(t *testing.T) (*genesis.Genesis, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	g := genesis.Devnet()
	g.ChainID = "b10coin-rt3-rotated-out"
	g.Params.ChainID = g.ChainID
	g.Params.EpochBlocks = rt3Epoch
	g.Params.CommitteeSize = rt3Committee
	minStake := g.Params.MinStakeSparks
	vals := make([]genesis.Validator, rt3Seats)
	for i := range vals {
		vals[i] = genesis.Validator{
			PubKey: simnet.ValidatorKey(i).Public().(ed25519.PublicKey),
			Power:  2 * minStake,
		}
	}
	g.Validators = vals
	joiner := simnet.ValidatorKey(rt3Seats)
	evictor := simnet.ValidatorKey(rt3Seats + 1)
	g.DevAccounts = []genesis.DevAccount{
		{PubKey: joiner.Public().(ed25519.PublicKey), BalanceSparks: minStake + g.Params.MinFeeSparks},
		{PubKey: evictor.Public().(ed25519.PublicKey), BalanceSparks: 3*minStake + g.Params.MinFeeSparks},
	}
	return g, joiner, evictor
}

func startRT3Validator(t *testing.T, g *genesis.Genesis, key ed25519.PrivateKey) *Validator {
	t.Helper()
	v, err := StartValidator(ValidatorConfig{
		Dir:       t.TempDir(),
		Genesis:   g,
		Key:       key,
		Listen:    "127.0.0.1:0",
		TickEvery: rt3Tick,
		WaveEvery: rt3Wave,
	})
	if err != nil {
		t.Fatalf("starting the RT-3 fixture validator: %v", err)
	}
	return v
}

func rt3BondTx(g *genesis.Genesis, priv ed25519.PrivateKey, amount, nonce uint64) types.Tx {
	pub := priv.Public().(ed25519.PublicKey)
	tx := types.Tx{
		Type: types.TxBond, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: nonce, Amount: amount, Fee: g.Params.MinFeeSparks,
	}
	h := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(priv, h[:])
	return tx
}

func rt3UnbondTx(g *genesis.Genesis, priv ed25519.PrivateKey, amount, nonce uint64) types.Tx {
	pub := priv.Public().(ed25519.PublicKey)
	tx := types.Tx{
		Type: types.TxUnbond, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: nonce, Amount: amount, Fee: 0,
	}
	h := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(priv, h[:])
	return tx
}

func submitToAll(t *testing.T, vs []*Validator, tx types.Tx) {
	t.Helper()
	for _, v := range vs {
		if errs := v.Pool().Add([]types.Tx{tx}); len(errs) != 0 && errs[0] != nil {
			t.Fatalf("submitting %s to %s: %v", tx.ID(), v.Addr(), errs[0])
		}
	}
}

// peerSees reports the height a peer's latest accepted HELLO from pub
// announced, and whether any acceptable HELLO is still remembered.
func peerSees(v *Validator, pub ed25519.PublicKey) (uint64, bool) {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	st := v.peerH[string(pub)]
	if st == nil {
		return 0, false
	}
	return st.height, true
}

// TestARotatedOutValidatorResyncsReannouncesAndIsCountedAgain is RT-3's
// end-to-end proof.
func TestARotatedOutValidatorResyncsReannouncesAndIsCountedAgain(t *testing.T) {
	g, joiner, evictor := rt3Genesis(t)
	joinerPub := joiner.Public().(ed25519.PublicKey)
	evictorPub := evictor.Public().(ed25519.PublicKey)
	joinerAddr := types.AddressFromPub(joinerPub)

	vs := make([]*Validator, rt3Seats)
	for i := 0; i < rt3Seats; i++ {
		vs[i] = startRT3Validator(t, g, simnet.ValidatorKey(i))
	}
	defer closeAll(vs[:rt3Seats])
	if err := connectMesh(vs); err != nil {
		t.Fatalf("connecting the genesis mesh: %v", err)
	}
	waitAllReach(t, vs, 2, 60*time.Second)

	// STEP 1: J bonds and epoch 1 seats it.
	minStake := g.Params.MinStakeSparks
	jtx := rt3BondTx(g, joiner, minStake, 0)
	submitToAll(t, vs, jtx)
	waitFor(t, "the joiner's Bond to commit", 90*time.Second, func() bool {
		for _, v := range vs {
			if v.Height() < 2 || v.Chain().State().Bonded(joinerAddr) != minStake {
				return false
			}
		}
		return true
	})
	b1 := (blockContaining(t, vs[0], jtx.ID())/rt3Epoch + 1) * rt3Epoch
	waitAllReach(t, vs, b1, 120*time.Second)
	for _, v := range vs {
		vals, err := v.Chain().CommitteeAt(b1)
		if err != nil {
			t.Fatalf("CommitteeAt(%d): %v", b1, err)
		}
		if genesis.SeatOfPubKey(vals, joinerPub) < 0 {
			t.Fatalf("epoch 1 (height %d) does not seat the joiner: the rotation-in never happened, so there is nothing to rotate out", b1)
		}
	}

	// STEP 2: J starts on a REPLAYED chain (no inherited lock or round) and is
	// counted in the epoch it was seated in.
	seed := seedChainFrom(t, g, vs[0].Chain(), b1)
	jn, err := StartValidator(ValidatorConfig{
		Dir: seed, Genesis: g, Key: joiner, Listen: "127.0.0.1:0",
		TickEvery: rt3Tick, WaveEvery: rt3Wave,
	})
	if err != nil {
		t.Fatalf("starting the joining node: %v", err)
	}
	defer jn.Close()
	for _, v := range vs {
		if err := jn.Connect(v.Addr()); err != nil {
			t.Fatalf("connecting the joining node: %v", err)
		}
	}
	all := append(append([]*Validator(nil), vs...), jn)
	waitFor(t, "the joining node to reach the epoch that seats it", 120*time.Second, func() bool {
		return jn.Height() >= b1+2
	})
	waitFor(t, "the joining node to vote after the boundary it was seated at", 90*time.Second, func() bool {
		for _, h := range jn.VotedHeights() {
			if h > b1 {
				return true
			}
		}
		return false
	})
	waitFor(t, "the joining node's precommit to be counted in a quorum certificate", 120*time.Second, func() bool {
		for h := b1; h <= jn.Height(); h++ {
			ok := true
			for _, v := range all {
				if v.Height() < h || !countedAt(t, v, h, joinerPub) {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	})

	// STEP 3: K bonds three times MIN_STAKE. The deciding state of the next
	// boundary holds K and J with unequal stakes, so the top six is the five
	// genesis keys plus K: J is rotated OUT.
	ktx := rt3BondTx(g, evictor, 3*minStake, 0)
	submitToAll(t, vs, ktx)
	waitFor(t, "the evictor's Bond to commit", 90*time.Second, func() bool {
		for _, v := range vs {
			if v.Height() < 2 || v.Chain().State().Bonded(types.AddressFromPub(evictorPub)) != 3*minStake {
				return false
			}
		}
		return true
	})
	b2 := (blockContaining(t, vs[0], ktx.ID())/rt3Epoch + 1) * rt3Epoch
	if b2 <= b1 {
		t.Fatalf("fixture: the evictor's bond decides epoch boundary %d, not after the joiner's %d", b2, b1)
	}
	waitAllReach(t, vs, b2, 120*time.Second)
	vals2, err := vs[0].Chain().CommitteeAt(b2)
	if err != nil {
		t.Fatalf("CommitteeAt(%d): %v", b2, err)
	}
	if genesis.SeatOfPubKey(vals2, evictorPub) < 0 {
		t.Fatalf("the boundary at %d does not seat the evictor: the rotation out was not constructed", b2)
	}
	if genesis.SeatOfPubKey(vals2, joinerPub) >= 0 {
		t.Fatalf("the boundary at %d still seats the joiner: the rotation out was not constructed", b2)
	}
	if jn.Chain().IsSeatedAt(b2, joinerPub) {
		t.Fatal("the joining node's own chain seats it at the boundary it was rotated out at")
	}

	// STEP 4: FROZEN-THEN-RECOVERED. J is seated nowhere at or after b2. The
	// ONE pull that crosses the boundary names an asker head in epoch 1 (where
	// J was a seat) and is authorised even by the old rule; every pull after
	// it names an epoch-2 head and only the ever-seated term admits it. So the
	// assertion is not "reached some height" - a single authorised pull can
	// carry J to whatever the peer's head was - but "kept following AFTER the
	// committee had already moved on": J must reach a height ABOVE the
	// committee's own at a settled snapshot. Without the sync half of RT-3 it
	// stops dead at the crossing height, because its next request is refused.
	waitFor(t, "the rotated-out validator to cross the boundary by adoption", 120*time.Second, func() bool {
		return jn.Height() >= b2+1
	})
	// Let any pull in flight land before taking the snapshot: a chain append
	// is per block, so a reader can otherwise catch a batch half-applied.
	time.Sleep(500 * time.Millisecond)
	_, peersNow := minMax(heightsOf(vs))
	if got := jn.Height(); got > peersNow {
		peersNow = got // J is a follower; this keeps the assertion honest anyway
	}
	waitFor(t, "the rotated-out validator to follow past the committee's settled height", 120*time.Second, func() bool {
		_, committeeAdvanced := minMax(heightsOf(vs))
		return jn.Height() > peersNow && committeeAdvanced > peersNow
	})
	unseatedHeight := jn.Height()
	if jn.Chain().IsSeatedAt(unseatedHeight, joinerPub) {
		t.Fatalf("fixture: the joining key is seated at height %d; the recovery was not exercised while rotated out", unseatedHeight)
	}
	waitFor(t, "the genesis peers to accept HELLOs announcing a height past the boundary", 90*time.Second, func() bool {
		for _, v := range vs {
			h, ok := peerSees(v, joinerPub)
			if !ok || h < b2+1 {
				return false
			}
		}
		return true
	})
	t.Logf("rotated out at %d: the member followed to height %d, past the committee's settled height %d, seated nowhere, and every genesis peer attested its post-boundary HELLO", b2, unseatedHeight, peersNow)

	// STEP 5: K unbonds fully in epoch 2, so epoch 3's deciding state holds
	// only the five genesis seats plus J: J is re-seated.
	utx := rt3UnbondTx(g, evictor, 3*minStake, 1)
	submitToAll(t, vs, utx)
	waitFor(t, "the evictor's Unbond to commit", 90*time.Second, func() bool {
		for _, v := range vs {
			if v.Height() < 2 || v.Chain().State().Bonded(types.AddressFromPub(evictorPub)) != 0 {
				return false
			}
		}
		return true
	})
	b3 := (blockContaining(t, vs[0], utx.ID())/rt3Epoch + 1) * rt3Epoch
	if b3 <= b2 {
		t.Fatalf("fixture: the evictor's unbond decides epoch boundary %d, not after the rotation out at %d", b3, b2)
	}
	waitAllReach(t, vs, b3, 120*time.Second)
	vals3, err := vs[0].Chain().CommitteeAt(b3)
	if err != nil {
		t.Fatalf("CommitteeAt(%d): %v", b3, err)
	}
	if genesis.SeatOfPubKey(vals3, joinerPub) < 0 {
		t.Fatalf("the boundary at %d does not re-seat the returning validator: the recovery's positive half was not constructed", b3)
	}
	if genesis.SeatOfPubKey(vals3, evictorPub) >= 0 {
		t.Fatalf("the boundary at %d still seats the evictor", b3)
	}

	// Counted again: the returning node follows a chain that now seats it,
	// rebuilds its driver, votes, and its precommit is in a certificate that
	// reaches that height's quorum.
	waitFor(t, "the returning validator to reach the epoch that re-seats it", 120*time.Second, func() bool {
		return jn.Height() >= b3+2
	})
	waitFor(t, "the returning validator to vote in the epoch that re-seats it", 90*time.Second, func() bool {
		for _, h := range jn.VotedHeights() {
			if h > b3 {
				return true
			}
		}
		return false
	})
	var proven uint64
	waitFor(t, "the returning validator's precommit to be counted in a quorum certificate again", 120*time.Second, func() bool {
		for h := b3 + 1; h <= jn.Height(); h++ {
			ok := true
			for _, v := range all {
				if v.Height() < h || !countedAt(t, v, h, joinerPub) {
					ok = false
					break
				}
			}
			if ok {
				proven = h
				return true
			}
		}
		return false
	})
	t.Logf("re-seated at %d: the returning validator's precommit is counted in the certificate at height %d", b3, proven)

	// THE BOUNDARY, on this same chain and head. committeeMemberAt is the
	// HELLO admission gate (admitHello and observeHello both call it); a key
	// that has never held a seat is still refused there, and has no
	// ever-seated record. The same call admits the rotated-out member, so what
	// widened is exactly "has ever held a seat".
	head := vs[0].Height()
	strangerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating the stranger key: %v", err)
	}
	if committeeMemberAt(vs[0].Chain(), g, strangerPub, head) {
		t.Fatalf("a key that never held a seat was admitted at height %d", head)
	}
	if vs[0].Chain().EverSeated(strangerPub) {
		t.Fatal("a key that never held a seat has an ever-seated record")
	}
	if !committeeMemberAt(vs[0].Chain(), g, joinerPub, head) {
		t.Fatalf("the rotated-out member is still refused at height %d: RT-3 is not fixed", head)
	}

	through := jn.Height()
	waitAllReach(t, all, through, 120*time.Second)
	assertIdenticalHistory(t, all, through)
}
