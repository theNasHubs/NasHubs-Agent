package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ensureCert loads a persisted self-signed TLS certificate from dataDir, or
// generates one on first boot and caches it. Returning a STABLE cert means the
// SHA-256 fingerprint the app pins at bootstrap stays valid across restarts.
//
// ECDSA P-256 is used (not Ed25519) for maximum TLS client compatibility; Ed25519
// is reserved for request signing where we control both ends.
func ensureCert(dataDir string) (tls.Certificate, string, error) {
	certPath := filepath.Join(dataDir, "agent.crt")
	keyPath := filepath.Join(dataDir, "agent.key")

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		fp, err := fingerprintOfFile(certPath)
		if err == nil {
			return cert, fp, nil
		}
	}
	// A missing/corrupt half of an existing identity must never silently rotate
	// the pin for every enrolled iOS/Android device. Require explicit recovery.
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return tls.Certificate{}, "", fmt.Errorf("existing TLS identity unavailable; restore certificate and key from backup")
		}
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("mkdir data dir: %w", err)
	}

	cert, der, err := generateSelfSigned()
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
		return tls.Certificate{}, "", err
	}
	keyBytes, _ := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyBytes); err != nil {
		return tls.Certificate{}, "", err
	}

	sum := sha256.Sum256(der)
	fp := base64.StdEncoding.EncodeToString(sum[:])
	return cert, fp, nil
}

func generateSelfSigned() (tls.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nashubs-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// No DNSNames/IPAddresses: the client pins this certificate by SHA-256
		// fingerprint and skips hostname validation, so it works for any NAS address.
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        cert,
	}, der, nil
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func fingerprintOfFile(certPath string) (string, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("bad pem")
	}
	sum := sha256.Sum256(block.Bytes)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}
