package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/libs4go/bcf4go/key"
	"github.com/overlaynetwork/onet-go"
	"github.com/pkg/errors"
	"golang.org/x/sys/cpu"
)

const certValidityPeriod = 100 * 365 * 24 * time.Hour // ~100 years
const certificatePrefix = "stf4go-transport-tls-handshake:"
const alpn string = "stf4go-transport-tls"

var extensionPrefix = []int{1, 3, 6, 1, 4, 1, 53594}

var extensionID = getPrefixedExtensionID([]int{1, 1})

func getPrefixedExtensionID(suffix []int) []int {
	return append(extensionPrefix, suffix...)
}

// extensionIDEqual compares two extension IDs.
func extensionIDEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type signedKey struct {
	Provider  string
	PubKey    []byte
	Signature []byte
}

func keyToCertificate(k key.Key) (*tls.Certificate, error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes := k.PubKey()

	certKeyPub, err := x509.MarshalPKIXPublicKey(certKey.Public())

	if err != nil {
		return nil, err
	}

	signature, err := key.SignWithKey(k, append([]byte(certificatePrefix), certKeyPub...))

	if err != nil {
		return nil, err
	}

	value, err := asn1.Marshal(signedKey{
		Provider:  k.Provider().Name(),
		PubKey:    keyBytes,
		Signature: signature,
	})

	if err != nil {
		return nil, err
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		NotBefore:    time.Time{},
		NotAfter:     time.Now().Add(certValidityPeriod),
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Value: value},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, certKey.Public(), certKey)

	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  certKey,
	}, nil
}

func newTLSConfig(key key.Key) (*tls.Config, chan []byte, error) {
	cert, err := keyToCertificate(key)
	if err != nil {
		return nil, nil, err
	}

	keyChan := make(chan []byte, 1)

	return &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: preferServerCipherSuites(),
		InsecureSkipVerify:       true, // This is not insecure here. We will verify the cert chain ourselves.
		ClientAuth:               tls.RequireAnyClientCert,
		Certificates:             []tls.Certificate{*cert},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {

			chain := make([]*x509.Certificate, len(rawCerts))
			for i := 0; i < len(rawCerts); i++ {
				cert, err := x509.ParseCertificate(rawCerts[i])
				if err != nil {
					return err
				}
				chain[i] = cert
			}

			pubKey, err := publicKeyFromCertChain(chain)

			if err != nil {
				return err
			}

			keyChan <- pubKey

			return nil
		},
		NextProtos:             []string{alpn},
		SessionTicketsDisabled: true,
	}, keyChan, nil
}

func publicKeyFromCertChain(chain []*x509.Certificate) ([]byte, error) {
	if len(chain) != 1 {
		return nil, errors.New("expected one certificates in the chain")
	}
	cert := chain[0]
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		// If we return an x509 error here, it will be sent on the wire.
		// Wrap the error to avoid that.
		return nil, fmt.Errorf("certificate verification failed: %s", err)
	}

	var found bool
	var keyExt pkix.Extension
	// find the libp2p key extension, skipping all unknown extensions
	for _, ext := range cert.Extensions {
		if extensionIDEqual(ext.Id, extensionID) {
			keyExt = ext
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("expected certificate to contain the key extension")
	}
	var sk signedKey
	if _, err := asn1.Unmarshal(keyExt.Value, &sk); err != nil {
		return nil, fmt.Errorf("unmarshalling signed certificate failed: %s", err)
	}

	certKeyPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	valid := key.Verify(sk.Provider, sk.PubKey, sk.Signature, append([]byte(certificatePrefix), certKeyPub...))

	if !valid {
		return nil, errors.Wrap(onet.ErrParams, "sign error")
	}

	return sk.PubKey, nil
}

// We want nodes without AES hardware (e.g. ARM) support to always use ChaCha.
// Only if both nodes have AES hardware support (e.g. x86), AES should be used.
// x86->x86: AES, ARM->x86: ChaCha, x86->ARM: ChaCha and ARM->ARM: Chacha
// This function returns true if we don't have AES hardware support, and false otherwise.
// Thus, ARM servers will always use their own cipher suite preferences (ChaCha first),
// and x86 servers will aways use the client's cipher suite preferences.
func preferServerCipherSuites() bool {
	// Copied from the Go TLS implementation.

	// Check the cpu flags for each platform that has optimized GCM implementations.
	// Worst case, these variables will just all be false.
	var (
		hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
		hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
		// Keep in sync with crypto/aes/cipher_s390x.go.
		hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

		hasGCMAsm = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
	)
	return !hasGCMAsm
}
