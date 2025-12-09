package cdxprops

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/xcrypto"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyAlgorithmInfo(t *testing.T) {
	tests := []struct {
		scenario string
		given    func(*testing.T) crypto.PublicKey
		then     string
	}{
		{
			scenario: "RSA Public Key",
			given: func(t *testing.T) crypto.PublicKey {
				cert, err := cdxtest.CertBuilder{}.
					WithSignatureAlgorithm(x509.SHA256WithRSA).
					Generate()
				require.NoError(t, err)
				return cert.Cert.PublicKey
			},
			then: "RSA-2048",
		},
		{
			scenario: "ECDSA Public Key",
			given: func(t *testing.T) crypto.PublicKey {
				cert, err := cdxtest.CertBuilder{}.
					WithSignatureAlgorithm(x509.ECDSAWithSHA256).
					Generate()
				require.NoError(t, err)
				return cert.Cert.PublicKey
			},
			then: "ECDSA-P-256",
		},
		{
			scenario: "Ed25519 Public Key",
			given: func(t *testing.T) crypto.PublicKey {
				cert, err := cdxtest.CertBuilder{}.
					WithSignatureAlgorithm(x509.PureEd25519).
					Generate()
				require.NoError(t, err)
				return cert.Cert.PublicKey
			},
			then: "Ed25519",
		},
		{
			scenario: "DSA-2048 Public Key",
			given: func(t *testing.T) crypto.PublicKey {
				return parseDer(t, cdxtest.DSA2048PublicKey)
			},
			then: "DSA-2048",
		},
		{
			scenario: "ML-DSA-65 Public Key",
			given: func(t *testing.T) crypto.PublicKey {
				return parseDer(t, cdxtest.MLDSA65PublicKey)
			},
			then: "ML-DSA-65",
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			t.Log(tt.scenario)

			pubKey := tt.given(t)
			pubKeyAlg := getPublicKeyAlgorithm(pubKey)

			info := publicKeyAlgorithmInfo(pubKeyAlg, pubKey)
			require.Equal(t, tt.then, info.name)
		})
	}
}

func parseDer(t *testing.T, name string) crypto.PublicKey {
	t.Helper()
	data, err := cdxtest.TestData(name)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "PUBLIC KEY", block.Type)
	pubKey, err := xcrypto.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return pubKey
}
