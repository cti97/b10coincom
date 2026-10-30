// PEER_EXCHANGE's relay pins. The relay is the one middlebox every validator
// trusts with no cryptographic relationship at all, so its value is exactly
// what it does NOT understand. Two tests keep the new message from changing
// that:
//
//   - the frame is forwarded byte-identically, like any other set of bytes the
//     relay cannot parse (it must not be special-cased, dropped, rewritten or
//     re-framed);
//   - the relay's SOURCE contains no decoder call and no import of the
//     consensus package, now or later - the property is checked structurally so
//     adding "just one decode" for PEER_EXCHANGE (or for anything else) cannot
//     land without failing here.
package relay

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/wire"
)

func TestTheRelayForwardsAPeerExchangeFrameUnchanged(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
	a := dial(t, r.Addr().String())
	b := dial(t, r.Addr().String())
	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")

	// A REAL frame: a height, an advertising key and a signature. The relay
	// must forward it byte-identically all the same - it may not know what
	// any of those fields are (audit PX-1).
	frame := wire.EncodePeerExchange(&wire.PeerExchange{
		Height:    7,
		Validator: bytes.Repeat([]byte{0xA5}, 32),
		Addrs: []string{
			"203.0.113.4:6001",
			"[2001:db8::7]:6002",
			"198.51.100.20:1",
		},
		Sig: bytes.Repeat([]byte{0x5A}, 64),
	})
	if len(frame) == 0 || wire.MsgType(frame[0]) != wire.MsgPeerExchange {
		t.Fatalf("the test frame does not open with the PEER_EXCHANGE tag: %x", frame)
	}
	writeFrame(t, a, frame)
	got := readFrame(t, b, 4096)
	if !bytes.Equal(got, frame) {
		t.Fatalf("the relayed PEER_EXCHANGE differs from the bytes sent (got %d B, want %d B) - the relay interpreted the frame it must stay ignorant of", len(got), len(frame))
	}
}

// TestTheRelayCallsNoDecoder is the "the relay still decodes nothing"
// acceptance check, made structural rather than observational: this package
// cannot report a decoder call it does not make, so the test reads the
// production sources and fails on the first `Decode*` call or on an import of
// the consensus package. A future "small fix" that parses a PEER_EXCHANGE tag
// here (or any other frame) fails on the next run rather than shipping a
// middlebox with an opinion about consensus.
func TestTheRelayCallsNoDecoder(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		checked++
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if strings.Contains(p, "internal/consensus") {
				t.Errorf("%s imports %s: the relay must not know the consensus message union", path, p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if strings.HasPrefix(name, "Decode") {
				t.Errorf("%s calls %s: the relay must make zero decoder calls", fset.Position(call.Pos()), name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no production source files were checked - the glob found only tests, so this property was not verified")
	}
}
