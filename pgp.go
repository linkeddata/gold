package gold

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Signer creates signatures that verify against a public key.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// Verifier verifies signatures against a public key.
type Verifier interface {
	Verify(data []byte, sig []byte) error
}

type rsaPubKey struct {
	*rsa.PublicKey
}

type rsaPrivKey struct {
	*rsa.PrivateKey
}

// ParsePublicKey parses a PEM encoded private key and returns an Verifier.
func ParsePublicKey(pemBytes []byte) (Verifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("No key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}

	return newVerifierFromKey(rawkey)
}

// ParsePublicKey parses a PEM encoded private key and returns a Signer.
func ParsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("No key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sKey = &rsaPrivKey{t}
	default:
		return nil, fmt.Errorf("Unsupported key type %T", k)
	}
	return sKey, nil
}

func newVerifierFromKey(k interface{}) (Verifier, error) {
	var uKey Verifier
	switch t := k.(type) {
	case *rsa.PublicKey:
		uKey = &rsaPubKey{t}
	default:
		return nil, fmt.Errorf("Unsupported key type %T", k)
	}
	return uKey, nil
}

// Sign signs data with rsa-sha256
func (r *rsaPrivKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}

// Verify verifies the message using a rsa-sha256 signature
func (r *rsaPubKey) Verify(message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}
