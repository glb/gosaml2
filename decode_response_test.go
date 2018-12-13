package saml2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

const idpCert = `
-----BEGIN CERTIFICATE-----
MIIDODCCAiCgAwIBAgIUQH54kyyeacU69J2iwz9bzeLmMaswDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSY29sbGVnZS5jY2N0Y2EuZWR1MB4XDTE1MDYwNDIyMTAz
MVoXDTM1MDYwNDIyMTAzMVowHTEbMBkGA1UEAwwSY29sbGVnZS5jY2N0Y2EuZWR1
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlJhN20ng2VN/cTrWtqUI
NaUsrHCkYXbm2y1PTN4b6fJI5hbvcv+LWCuLkLi3+iPGlBpcHHfrdJcyhmBHRHQ9
Sos3RIH5Lsn1IgjWe3hxQQmVeEi5xVxnw2YZGHaeX4YnI1TEBJwhtJmyitk74LHy
bPGEqOJdApUnLz54L7I+252G/cOfEqUHMbxxtmHSc/9chF8bBxQ8OzIbJsByHnqi
awQHwtsttre7n328gVqmf1VHE27cfAYiSjuK5pCsx/1kuJMBN+kg/3Gg9oi6aR50
WX1VUF3IBcnTDeiAXRz3PgsT8FlVZou6Ik9NT/Y5IHOZVGk64SRDaG8FuGxLexXr
swIDAQABo3AwbjAdBgNVHQ4EFgQUjQwaAoY3u/iToIE3ADeNEW+Uu34wTQYDVR0R
BEYwRIISY29sbGVnZS5jY2N0Y2EuZWR1hi5odHRwczovL2NvbGxlZ2UuY2NjdGNh
LmVkdTo4NDQzL2lkcC9zaGliYm9sZXRoMA0GCSqGSIb3DQEBCwUAA4IBAQB26rdx
phN1YKad3yDhLg6Y1ZwbmAjc+l4QB1KSL+cLqhDn5iMy4VdWh8HpSKRqCwofLtlw
3qOwospj+mJaguXRMpjYODRQaKRkTrCGxJhuNrQxDXL/b6FOEIJnUYenbPevuNgR
Jc1VnREhWUUXT44KN5YUz9FEiG0BsBK8ecCPKBzTQ/hwaczhpqw6uqVMqxJaTGcn
lCUHJAhVHiA8lWJ7vaNPsJ86xBFs/F76EwyFXIKQaruvcvChU7GNNSYdNJBa6HO9
9QWdGbr5aNQ4diunnBQdrdjgbQIwyhKTfbFWa2l5vbqEKDc0dwuPa6c25l8ruqxq
CQ1CF8ZDDJ0XV6Ab
-----END CERTIFICATE-----
`

const oktaCert = `
-----BEGIN CERTIFICATE-----
MIIDPDCCAiQCCQDydJgOlszqbzANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJVUzETMB
EGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEQMA4GA1UEChMH
SmFua3lDbzESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE0MDMxMjE5NDYzM1oXDTI3MTExOT
E5NDYzM1owYDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DVNhbiBGcmFuY2lzY28xEDAOBgNVBAoTB0phbmt5Q28xEjAQBgNVBAMTCWxvY2FsaG9zdD
CCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMGvJpRTTasRUSPqcbqCG+ZnTAur
nu0vVpIG9lzExnh11o/BGmzu7lB+yLHcEdwrKBBmpepDBPCYxpVajvuEhZdKFx/Fdy6j5m
H3rrW0Bh/zd36CoUNjbbhHyTjeM7FN2yF3u9lcyubuvOzr3B3gX66IwJlU46+wzcQVhSOl
Mk2tXR+fIKQExFrOuK9tbX3JIBUqItpI+HnAow509CnM134svw8PTFLkR6/CcMqnDfDK1m
993PyoC1Y+N4X9XkhSmEQoAlAHPI5LHrvuujM13nvtoVYvKYoj7ScgumkpWNEvX652LfXO
nKYlkB8ZybuxmFfIkzedQrbJsyOhfL03cMECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAeH
wzqwnzGEkxjzSD47imXaTqtYyETZow7XwBc0ZaFS50qRFJUgKTAmKS1xQBP/qHpStsROT3
5DUxJAE6NY1Kbq3ZbCuhGoSlY0L7VzVT5tpu4EY8+Dq/u2EjRmmhoL7UkskvIZ2n1DdERt
d+YUMTeqYl9co43csZwDno/IKomeN5qaPc39IZjikJ+nUC6kPFKeu/3j9rgHNlRtocI6S1
FdtFz9OZMQlpr0JbUt2T3xS/YoQJn6coDmJL5GTiiKM6cOe+Ur1VwzS1JEDbSS2TWWhzq8
ojLdrotYLGd9JOsoQhElmz+tMfCFQUFLExinPAyy7YHlSiVX13QH2XTu/iQQ==
-----END CERTIFICATE-----
`

func testEncryptedAssertion(t *testing.T, validateEncryptionCert bool) {
	var err error
	cert, err := tls.LoadX509KeyPair("./testdata/test.crt", "./testdata/test.key")
	require.NoError(t, err, "could not load x509 key pair")

	block, _ := pem.Decode([]byte(idpCert))

	idpCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse idp cert pem block")

	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: "https://saml2.test.astuart.co/sso/saml2",
		SPKeyStore:                  dsig.TLSCertKeyStore(cert),
		ValidateEncryptionCert:      validateEncryptionCert,
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{idpCert},
		},
		Clock: dsig.NewFakeClockAt(time.Date(2016, 04, 28, 22, 00, 00, 00, time.UTC)),
	}

	bs, err := ioutil.ReadFile("./testdata/saml.post")
	require.NoError(t, err, "couldn't read post")

	_, err = sp.RetrieveAssertionInfo(string(bs))
	if validateEncryptionCert {
		require.Error(t, err)
		require.Equal(t, "error validating response: unable to get decryption certificate: decryption cert is not valid at this time", err.Error())
	} else {
		require.NoError(t, err, "Assertion info should be retrieved with no error")
	}
}

func TestEncryptedAssertion(t *testing.T) {
	testEncryptedAssertion(t, false)
}

func TestEncryptedAssertionInvalidCert(t *testing.T) {
	testEncryptedAssertion(t, true)
}

func TestCompressedResponse(t *testing.T) {
	bs, err := ioutil.ReadFile("./testdata/saml_compressed.post")
	require.NoError(t, err, "couldn't read compressed post")

	block, _ := pem.Decode([]byte(oktaCert))

	idpCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse okta cert pem block")

	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: "https://f1f51ddc.ngrok.io/api/sso/saml2/acs/58cafd0573d4f375b8e70e8e",
		SPKeyStore:                  dsig.TLSCertKeyStore(cert),
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{idpCert},
		},
		Clock: dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2017, 3, 17, 20, 00, 0, 0, time.UTC))),
	}

	_, err = sp.RetrieveAssertionInfo(string(bs))
	require.NoError(t, err, "Assertion info should be retrieved with no error")
}

func Test_SAMLServiceProvider_GetDecryptCert(t *testing.T) {
	tcs := []struct {
		name             string
		actualClockSkew  time.Duration
		allowedClockSkew time.Duration
		expiry           time.Duration
		check            func(t *testing.T, cert *tls.Certificate, err error)
	}{
		{
			name: "no actual clock skew, no allowed clock skew, should have no error",
			check: func(t *testing.T, cert *tls.Certificate, err error) {
				require.NoError(t, err)
				require.NotNil(t, cert)
			},
		},
		{
			name:             "no actual clock skew, some allowed clock skew, should have no error",
			allowedClockSkew: 30 * time.Second,
			check: func(t *testing.T, cert *tls.Certificate, err error) {
				require.NoError(t, err)
				require.NotNil(t, cert)
			},
		},
		{
			name:             "actual clock skew within bounds, some allowed clock skew, should have no error",
			actualClockSkew:  10 * time.Second,
			allowedClockSkew: 30 * time.Second,
			check: func(t *testing.T, cert *tls.Certificate, err error) {
				require.NoError(t, err)
				require.NotNil(t, cert)
			},
		},
		{
			name:             "actual clock skew outside bounds, some allowed clock skew, should have error",
			actualClockSkew:  60 * time.Second,
			allowedClockSkew: 30 * time.Second,
			check: func(t *testing.T, cert *tls.Certificate, err error) {
				require.EqualError(t, err, "decryption cert is not valid at this time")
				require.Nil(t, cert)
			},
		},
		{
			name:             "allowed skew should not affect certificate NotOnOrAfter evaluation",
			expiry:           -10 * time.Second,
			allowedClockSkew: 30 * time.Second,
			check: func(t *testing.T, cert *tls.Certificate, err error) {
				require.EqualError(t, err, "decryption cert is not valid at this time")
				require.Nil(t, cert)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()

			expiry := 365 * 24 * time.Hour
			if tc.expiry != 0 {
				expiry = tc.expiry
			}

			ks := randomKeyStoreForTestWithValidityPeriod(now.Add(tc.actualClockSkew), now.Add(expiry))

			sp := &SAMLServiceProvider{
				SPKeyStore:             ks,
				ValidateEncryptionCert: true,
				AllowedClockSkew:       tc.allowedClockSkew,
			}

			cert, err := sp.getDecryptCert()

			tc.check(t, cert, err)
		})
	}
}

func randomKeyStoreForTestWithValidityPeriod(notBefore, notAfter time.Time) dsig.X509KeyStore {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	return &TestKeyStore{
		privateKey: key,
		cert:       cert,
	}
}

type TestKeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (ks *TestKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.cert, nil
}
