package cdxprops

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/xcrypto"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"github.com/stretchr/testify/require"
)

func TestPrivateKeyAlgorithmInfo(t *testing.T) {
	type then struct {
		name   string
		pubKey crypto.PrivateKey
	}
	tests := []struct {
		scenario string
		given    func(*testing.T) crypto.PrivateKey
		then     then
	}{
		{
			scenario: "RSA Private Key",
			given: func(t *testing.T) crypto.PrivateKey {
				cert, err := cdxtest.CertBuilder{}.
					WithSignatureAlgorithm(x509.SHA256WithRSA).
					Generate()
				require.NoError(t, err)
				return cert.Key
			},
			then: then{
				name:   "RSA-2048",
				pubKey: new(rsa.PublicKey),
			},
		},
		{
			scenario: "ECDSA Private Key",
			given: func(t *testing.T) crypto.PrivateKey {
				cert, err := cdxtest.CertBuilder{}.
					WithSignatureAlgorithm(x509.ECDSAWithSHA256).
					Generate()
				require.NoError(t, err)
				return cert.Key
			},
			then: then{
				name:   "ECDSA-P-256",
				pubKey: new(ecdsa.PublicKey),
			},
		},
		{
			scenario: "Ed25519 Private Key",
			given: func(t *testing.T) crypto.PrivateKey {
				cert, err := cdxtest.CertBuilder{}.
					WithSignatureAlgorithm(x509.PureEd25519).
					Generate()
				require.NoError(t, err)
				return cert.Key
			},
			then: then{
				name:   "Ed25519",
				pubKey: ed25519.PublicKey{},
			},
		},
		{
			scenario: "ML-DSA-44 Private Key",
			given: func(t *testing.T) crypto.PrivateKey {
				return parsePrivateKey(t, cdxtest.MLDSA44PrivateKey)
			},
			then: then{
				name:   "ML-DSA-44",
				pubKey: new(mldsa44.PublicKey),
			},
		},
		{
			scenario: "ML-DSA-65 Private Key",
			given: func(t *testing.T) crypto.PrivateKey {
				return parsePrivateKey(t, cdxtest.MLDSA65PrivateKey)
			},
			then: then{
				name:   "ML-DSA-65",
				pubKey: new(mldsa65.PublicKey),
			},
		},
		{
			scenario: "ML-DSA-87 Private Key",
			given: func(t *testing.T) crypto.PrivateKey {
				return parsePrivateKey(t, cdxtest.MLDSA87PrivateKey)
			},
			then: then{
				name:   "ML-DSA-87",
				pubKey: new(mldsa87.PublicKey),
			},
		},
		{
			scenario: "unknown",
			given: func(_ *testing.T) crypto.PrivateKey {
				type unknown struct{}
				return unknown{}
			},
			then: then{
				name: "Unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			t.Log(tt.scenario)

			privKey := tt.given(t)
			info := privateKeyInfo(privKey)

			require.Equal(t, tt.then.name, info.name)
			pubKey, err := getPublicKey(privKey)
			if info.name == "Unknown" {
				require.Error(t, err)
				return
			}

			t.Logf("tt.then.pubKey %T", tt.then.pubKey)
			t.Logf("pubKey %T", pubKey)
			require.IsType(t, tt.then.pubKey, pubKey)
		})
	}
}

func parsePrivateKey(t *testing.T, name string) crypto.PrivateKey {
	t.Helper()
	data, err := cdxtest.TestData(name)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "PRIVATE KEY", block.Type)
	pubKey, err := xcrypto.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return pubKey
}
