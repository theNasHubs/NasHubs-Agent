// Command nashubs-probe is a test client that mirrors the iOS AgentTransport:
// it generates (or loads) an Ed25519 keypair, pairs with a running agent, then
// deploys a hello-world compose and prints the streamed logs. Used for the
// end-to-end NAS test without driving the iOS app.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	hdrKeyID = "X-NasHubs-Keyid"
	hdrTs    = "X-NasHubs-Ts"
	hdrNonce = "X-NasHubs-Nonce"
	hdrSig   = "X-NasHubs-Sig"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		keygen()
	case "test":
		testCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  nashubs-probe keygen\n  nashubs-probe test -url https://HOST:8443 -secret SECRET")
	os.Exit(2)
}

// keygen writes a seed to NASHUBS_PROBE_KEYFILE (default ./nashubs-probe.key) and
// prints the base64 public key (to set as NASHUBS_TRUSTED_PUBKEY) + a new secret.
func keygen() {
	keyfile := envOr("NASHUBS_PROBE_KEYFILE", "nashubs-probe.key")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	must(os.WriteFile(keyfile, priv, 0o600))
	secret := randSecret()
	fmt.Printf("NASHUBS_TRUSTED_PUBKEY=%s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("NASHUBS_PAIRING_SECRET=%s\n", secret)
	fmt.Printf("(wrote private key to %s)\n", keyfile)
}

func testCmd(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	url := fs.String("url", "", "agent base url, e.g. https://10.10.10.30:8443")
	secret := fs.String("secret", "", "pairing secret")
	fs.Parse(args)
	if *url == "" || *secret == "" {
		usage()
	}
	keyfile := envOr("NASHUBS_PROBE_KEYFILE", "nashubs-probe.key")
	raw, err := os.ReadFile(keyfile)
	must(err)
	priv := ed25519.PrivateKey(raw) // full 64-byte private key written by keygen

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	// 1) Pair.
	pairBody, _ := json.Marshal(map[string]string{"pairingSecret": *secret})
	pr, _ := doSigned(client, priv, "POST", *url+"/pair", pairBody)
	fmt.Printf("[pair] %d %s\n", pr.status, trunc(pr.body))
	if pr.status != 200 {
		fail("pair failed")
	}

	// 2) Deploy hello-world.
	compose := "services:\n  hello:\n    image: hello-world\n"
	depBody, _ := json.Marshal(map[string]string{"id": "hello", "compose": compose})
	dr, _ := doSigned(client, priv, "POST", *url+"/deploy", depBody)
	fmt.Printf("[deploy] %d %s\n", dr.status, trunc(dr.body))
	if dr.status != 200 {
		fail("deploy failed")
	}

	// 3) Health.
	time.Sleep(2 * time.Second)
	hr, _ := doSigned(client, priv, "GET", *url+"/health/hello", nil)
	fmt.Printf("[health] %d %s\n", hr.status, trunc(hr.body))

	// 4) Logs (one-shot, no follow).
	lr, _ := doSigned(client, priv, "GET", *url+"/logs/hello", nil)
	fmt.Printf("[logs] %d\n%s\n", lr.status, lr.body)

	fmt.Println("\n✅ END-TO-END OK — agent deployed hello-world on the NAS")
}

// --- signed request (mirrors agent auth.go + iOS AgentTransport exactly) ---

type resp struct {
	status int
	body   string
}

func doSigned(c *http.Client, priv ed25519.PrivateKey, method, url string, body []byte) (resp, error) {
	if body == nil {
		body = []byte{}
	}
	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonce := base64.StdEncoding.EncodeToString(randBytes(16))
	sum := sha256.Sum256(body)
	base := []byte(method + "\n" + pathOf(url) + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
	sig := ed25519.Sign(priv, base)
	pub := priv.Public().(ed25519.PublicKey)

	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	req.Header.Set(hdrKeyID, base64.StdEncoding.EncodeToString(pub))
	req.Header.Set(hdrTs, ts)
	req.Header.Set(hdrNonce, nonce)
	req.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(sig))
	r, err := c.Do(req)
	if err != nil {
		return resp{status: 0, body: err.Error()}, err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{status: r.StatusCode, body: string(b)}, nil
}

func pathOf(u string) string {
	scheme := strings.Index(u, "://")
	start := scheme + 3
	slash := strings.IndexByte(u[start:], '/')
	if slash < 0 {
		return "/"
	}
	p := u[start+slash:]
	if q := strings.IndexByte(p, '?'); q >= 0 {
		p = p[:q]
	}
	return p
}

func randBytes(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
func randSecret() string {
	b := randBytes(18)
	return base64.RawURLEncoding.EncodeToString(b)
}
func envOr(k, d string) string { if v := os.Getenv(k); v != "" { return v }; return d }
func must(err error)            { if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) } }
func fail(m string)             { fmt.Fprintln(os.Stderr, "❌", m); os.Exit(1) }
func trunc(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
