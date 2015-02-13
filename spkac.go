package gold

import (
	"bytes"
	// "crypto/ecdsa"
	// "crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
)

type pkacInfo struct {
	Raw       asn1.RawContent
	PublicKey publicKeyInfo
	Challenge string
}

type spkacInfo struct {
	Raw       asn1.RawContent
	Pkac      pkacInfo
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

type rsaPublicKey struct {
	N *big.Int
	E int
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

var (
	oidPublicKeyRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

func parsePublicKey(algo x509.PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	switch algo {
	case x509.RSA:
		p := new(rsaPublicKey)
		_, err := asn1.Unmarshal(asn1Data, p)
		if err != nil {
			return nil, err
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	default:
		// DSA and EC not supported everywhere
		return nil, nil
	}
}

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.PublicKeyAlgorithm {
	if oid.Equal(oidPublicKeyRSA) {
		return x509.RSA
	}
	return x509.UnknownPublicKeyAlgorithm
}

// ParseSPKAC returns the public key from a KEYGEN's SPKAC request
func ParseSPKAC(spkacBase64 string) (pub interface{}, err error) {
	var info spkacInfo
	derBytes, err := base64.StdEncoding.DecodeString(spkacBase64)
	if err != nil {
		return nil, err
	}

	if _, err = asn1.Unmarshal(derBytes, &info); err != nil {
		return
	}

	algo := getPublicKeyAlgorithmFromOID(info.Pkac.PublicKey.Algorithm.Algorithm)
	if algo == x509.UnknownPublicKeyAlgorithm {
		return nil, errors.New("x509: unknown public key algorithm")
	}

	pub, err = parsePublicKey(algo, &info.Pkac.PublicKey)
	if err != nil {
		return
	}

	return
}

// NewSPKACx509 creates a new x509 self-signed cert based on the SPKAC value
func NewSPKACx509(uri string, name string, spkacBase64 string) ([]byte, error) {
	public, err := ParseSPKAC(spkacBase64)
	if err != nil {
		return nil, err
	}
	pubKey := public.(*rsa.PublicKey)
	rsaPub, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	pubSha1 := h.Sum(rsaPub)[:20]

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(42),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"WebID"},
			// Country:      []string{"US"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		SubjectKeyId: pubSha1,

		BasicConstraintsValid: true,
	}
	// add WebID in the subjectAltName field
	var rawValues []asn1.RawValue
	rawValues = append(rawValues, asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(uri)})
	values, err := asn1.Marshal(rawValues)
	if err != nil {
		return nil, err
	}
	template.ExtraExtensions = []pkix.Extension{{Id: subjectAltName, Value: values}}
	template.Extensions = template.ExtraExtensions
	certDerBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, public, priv)

	return certDerBytes, nil
}

// NewRSAcert creates a new RSA x509 self-signed certificate
func NewRSAcert(uri string, name string, priv *rsa.PrivateKey) (*tls.Certificate, error) {
	uri = "URI: " + uri
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(42),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"WebID"},
			// Country:      []string{"US"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	rawValues := []asn1.RawValue{
		{Class: 2, Tag: 6, Bytes: []byte(uri)},
	}
	values, err := asn1.Marshal(rawValues)
	if err != nil {
		return nil, err
	}
	template.ExtraExtensions = []pkix.Extension{{Id: subjectAltName, Value: values}}

	keyPEM := bytes.NewBuffer(nil)
	err = pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := bytes.NewBuffer(nil)
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
