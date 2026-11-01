package rpc

// Audit R-3 and T-2 (2026-11-01): what the faucet page does with the two
// strings a stranger controls, the address field and the Host header.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
)

// TestFaucetPageRefusesAKeyHoweverItIsPasted: the refusal-by-name must hold
// for every way a key reaches a single-line form, not only for a bare hex
// string. A pasted key file loses its newlines in the input, a key may carry
// a 0x prefix or quotes, and a trailing space is the commonest paste
// artefact. None of them may put a byte of the key into the page.
func TestFaucetPageRefusesAKeyHoweverItIsPasted(t *testing.T) {
	_, ts := pageServer(t, genesis.Devnet())
	priv := strings.Repeat("ab", 64)
	pub := strings.Repeat("cd", 32)
	for name, raw := range map[string]string{
		"json key file":  `{ "version": 1, "private_key": "` + priv + `", "public_key": "` + pub + `" }`,
		"0x prefixed":    "0x" + priv,
		"padded":         " " + priv + " ",
		"quoted":         `"` + priv + `"`,
		"upper case":     strings.ToUpper(priv),
		"public, padded": pub + "\t",
	} {
		t.Run(name, func(t *testing.T) {
			body, resp := getPage(t, ts.URL+"/faucet?address="+url.QueryEscape(raw))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /faucet = %d, want 200", resp.StatusCode)
			}
			if !strings.Contains(body, "never paste a key") {
				t.Errorf("the refusal does not say never to paste a key; body:\n%s", body)
			}
			for _, secret := range []string{priv[:16], strings.ToUpper(priv[:16]), pub[:16]} {
				if strings.Contains(body, secret) {
					t.Errorf("the page echoed %q from the pasted secret (audit R-3); body:\n%s", secret, body)
				}
			}
		})
	}
}

// TestFaucetNodeURLKeepsAHostileHostHeaderOutOfTheCommandLine pins the
// sanitiser behind the `b10coin claim --node ...` line a reader pastes into a
// shell (audit T-2): only an IP or a DNS-shaped host with a numeric port is
// rendered; anything else falls back to the default.
func TestFaucetNodeURLKeepsAHostileHostHeaderOutOfTheCommandLine(t *testing.T) {
	for host, want := range map[string]string{
		"127.0.0.1:8645":          "http://127.0.0.1:8645",
		"pi-a.local:8645":         "http://pi-a.local:8645",
		"[::1]:8645":              "http://[::1]:8645",
		"127.0.0.1:8645;$(id)":    defaultNodeURL,
		"a@b:80":                  defaultNodeURL,
		"x:99999":                 defaultNodeURL,
		"x:0":                     defaultNodeURL,
		"evil.example/#:8645":     defaultNodeURL,
		"127.0.0.1":               defaultNodeURL,
		"":                        defaultNodeURL,
		"127.0.0.1:8645 --key /x": defaultNodeURL,
	} {
		req := httptest.NewRequest(http.MethodGet, "/faucet", nil)
		req.Host = host
		if got := faucetNodeURL(req); got != want {
			t.Errorf("Host %q rendered as %q, want %q", host, got, want)
		}
	}
}
