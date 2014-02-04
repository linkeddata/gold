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
	"github.com/stretchr/testify/assert"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestWebIDTLSAuth(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	assert.NoError(t, err, "failed to generate private key: %s", err)

	userUri := testServer.URL + "/webid#user"
	userTerm := rdf.NewResource(userUri)
	keyTerm := rdf.NewResource(testServer.URL + "/webid#key")
	g := NewGraph(testServer.URL + "/webid")
	g.AddTriple(userTerm, ns["cert"].Get("key"), keyTerm)
	g.AddTriple(keyTerm, ns["rdf"].Get("type"), ns["cert"].Get("RSAPublicKey"))
	g.AddTriple(keyTerm, ns["cert"].Get("modulus"), rdf.NewLiteral(fmt.Sprintf("%x", priv.N)))
	g.AddTriple(keyTerm, ns["cert"].Get("exponent"), rdf.NewLiteral(fmt.Sprintf("%d", priv.E)))
	gN3, _ := g.Write("text/turtle")

	req, err := http.NewRequest("PUT", g.URI(), strings.NewReader(gN3))
	assert.NoError(t, err)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, resp.StatusCode, 201)

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
		asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: []byte(userUri)},
	}
	values, err := asn1.Marshal(rawValues)
	assert.NoError(t, err)
	template.ExtraExtensions = []pkix.Extension{pkix.Extension{Id: subjectAltName, Value: values}}

	keyPEM := bytes.NewBuffer(nil)
	err = pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	assert.NoError(t, err)

	certPEM := bytes.NewBuffer(nil)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err)
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	assert.NoError(t, err)

	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	assert.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
				Rand:               rand.Reader,
			},
		},
	}

	req, err = http.NewRequest("DELETE", g.URI(), nil)
	assert.NoError(t, err)
	resp, err = client.Do(req)
	assert.NoError(t, err)
	if resp != nil {
		assert.Equal(t, resp.StatusCode, 200)
		assert.Equal(t, resp.Header.Get("User"), userUri)
	}
}
