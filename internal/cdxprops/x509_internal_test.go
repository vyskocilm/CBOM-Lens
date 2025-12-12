package cdxprops

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/stretchr/testify/require"
)

func Test_spkiOID(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := spkiOID(selfSigned.Cert)
	require.Equal(t, "1.2.840.113549.1.1.1", res)

	selfSigned.Cert.RawSubjectPublicKeyInfo = []byte("garbage")
	res = spkiOID(selfSigned.Cert)
	require.Equal(t, "", res)
}

func Test_readSignatureAlgorithmRef(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "")
	exp := cdx.BOMReference("crypto/algorithm/sha-256-rsa@1.2.840.113549.1.1.11")
	require.Equal(t, exp, res)

	selfSigned.Cert.SignatureAlgorithm = -1
	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "2.16.840.1.101.3.4.3.17")
	exp = cdx.BOMReference("crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17")
	require.Equal(t, exp, res)

}
