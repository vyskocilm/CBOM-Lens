package xcrypto_test

import (
	"crypto"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/xcrypto"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/require"
)

func TestParsePKIXPublicKey(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		given    func(*testing.T) []byte
		then     func(*testing.T, crypto.PublicKey)
	}{
		{
			name:     "ML-DSA-44",
			scenario: "parse PKIX encoded ML-DSA-44 public key",
			given: func(t *testing.T) []byte {
				data, err := cdxtest.TestData(cdxtest.MLDSA44PublicKey)
				require.NoError(t, err)
				block, _ := pem.Decode(data)
				require.NotNil(t, block)
				require.Equal(t, "PUBLIC KEY", block.Type)
				return block.Bytes
			},
			then: func(t *testing.T, pubKey crypto.PublicKey) {
				publicKey, ok := pubKey.(*mldsa44.PublicKey)
				require.True(t, ok)
				h := hashPublicKey(t, publicKey)
				require.Equal(t, cdxtest.MLDSA44PublicKeyHash, hex.EncodeToString(h))
			},
		},
		{
			name:     "ML-DSA-65",
			scenario: "parse PKIX encoded ML-DSA-65 public key",
			given: func(t *testing.T) []byte {
				data, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
				require.NoError(t, err)
				block, _ := pem.Decode(data)
				require.NotNil(t, block)
				require.Equal(t, "PUBLIC KEY", block.Type)
				return block.Bytes
			},
			then: func(t *testing.T, pubKey crypto.PublicKey) {
				publicKey, ok := pubKey.(*mldsa65.PublicKey)
				require.True(t, ok)
				h := hashPublicKey(t, publicKey)
				require.Equal(t, cdxtest.MLDSA65PublicKeyHash, hex.EncodeToString(h))
			},
		},
		{
			name:     "ML-DSA-87",
			scenario: "parse PKIX encoded ML-DSA-87 public key",
			given: func(t *testing.T) []byte {
				data, err := cdxtest.TestData(cdxtest.MLDSA87PublicKey)
				require.NoError(t, err)
				block, _ := pem.Decode(data)
				require.NotNil(t, block)
				require.Equal(t, "PUBLIC KEY", block.Type)
				return block.Bytes
			},
			then: func(t *testing.T, pubKey crypto.PublicKey) {
				publicKey, ok := pubKey.(*mldsa87.PublicKey)
				require.True(t, ok)
				h := hashPublicKey(t, publicKey)
				require.Equal(t, cdxtest.MLDSA87PublicKeyHash, hex.EncodeToString(h))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Log(tt.scenario)

			pkixBytes := tt.given(t)
			cryptoPublicKey, err := xcrypto.ParsePKIXPublicKey(pkixBytes)
			require.NoError(t, err)

			tt.then(t, cryptoPublicKey)
		})
	}
}
