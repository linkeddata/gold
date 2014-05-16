package gold

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	rdf "github.com/kierdavis/argo"
	"math/big"
	"net/http/httptest"
	"time"
)

const (
	rsaBits = 1024
)

var (
	notBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)

	testServer = httptest.NewUnstartedServer(handler)
)

func init() {
	testServer.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
		NextProtos: []string{"http/1.1"},
		Rand:       rand.Reader,
	}
	testServer.StartTLS()
}

func newRSA(uri string) (*Graph, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}

	userTerm := rdf.NewResource(uri)
	keyTerm := rdf.NewResource(testServer.URL + "/_test/webid#key")
	g := NewGraph(testServer.URL + "/_test/webid")
	g.AddTriple(userTerm, ns["cert"].Get("key"), keyTerm)
	g.AddTriple(keyTerm, ns["rdf"].Get("type"), ns["cert"].Get("RSAPublicKey"))
	g.AddTriple(keyTerm, ns["cert"].Get("modulus"), rdf.NewLiteral(fmt.Sprintf("%x", priv.N)))
	g.AddTriple(keyTerm, ns["cert"].Get("exponent"), rdf.NewLiteral(fmt.Sprintf("%d", priv.E)))
	return g, priv, nil
}

func newRSAcert(uri string, priv *rsa.PrivateKey) (*tls.Certificate, error) {
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   "Test",
			Organization: []string{"WebID"},
			Country:      []string{"US"},
		},
		// MaxPathLen: -1,
		NotBefore: notBefore,
		NotAfter:  notAfter,

		BasicConstraintsValid: true,
		// KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		// ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	rawValues := []asn1.RawValue{
		asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: []byte(uri)},
	}
	values, err := asn1.Marshal(rawValues)
	if err != nil {
		return nil, err
	}
	template.ExtraExtensions = []pkix.Extension{pkix.Extension{Id: subjectAltName, Value: values}}

	keyPEM := bytes.NewBuffer(nil)
	err = pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return nil, err
	}

	certPEM := bytes.NewBuffer(nil)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
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
