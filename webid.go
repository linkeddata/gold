package gold

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	rsaBits = 2048
)

type webidAccount struct {
	URI      string
	Name     string
	Email    string
	Img      string
	Modulus  string
	Exponent string
}

var (
	subjectAltName = []int{2, 5, 29, 17}

	notBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)

	// cache
	webidL  = new(sync.Mutex)
	pkeyURI = map[string]string{}
)

func pkeyTypeNE(pkey interface{}) (t, n, e string) {
	switch pkey := pkey.(type) {
	//TODO: case *dsa.PublicKey
	case *rsa.PublicKey:
		t = "RSAPublicKey"
		n = fmt.Sprintf("%x", pkey.N)
		e = fmt.Sprintf("%d", pkey.E)
	}
	return
}

// WebIDTLSAuth - performs WebID-TLS authentication
func WebIDTLSAuth(tls *tls.ConnectionState) (uri string, err error) {
	claim := ""
	uri = ""
	err = nil

	if tls == nil || !tls.HandshakeComplete {
		return "", errors.New("Not a TLS connection. TLS handshake failed")
	}

	if len(tls.PeerCertificates) < 1 {
		return "", errors.New("No client certificate found in the TLS request!")
	}

	for _, x := range tls.PeerCertificates[0].Extensions {
		if !x.Id.Equal(subjectAltName) {
			continue
		}
		if len(x.Value) < 5 {
			continue
		}

		v := asn1.RawValue{}
		_, err = asn1.Unmarshal(x.Value, &v)
		if err == nil {
			if strings.Contains(string(v.Bytes), "URI:") {
				claim = string(v.Bytes[7:])
			} else {
				claim = string(v.Bytes[2:])
			}
		}
		if len(claim) == 0 {
			continue
		}

		pkey := tls.PeerCertificates[0].PublicKey
		t, n, e := pkeyTypeNE(pkey)
		if len(t) == 0 {
			continue
		}

		// DebugLog("WebID-TLS", "Found public key from client containing WebID claim: "+claim)

		pkeyk := fmt.Sprint([]string{t, n, e})
		webidL.Lock()
		uri = pkeyURI[pkeyk]
		webidL.Unlock()
		if len(uri) > 0 {
			return
		}

		g := NewGraph(claim)
		err = g.LoadURI(claim)
		if err != nil {
			return "", err
		}

		for _, keyT := range g.All(NewResource(claim), ns.cert.Get("key"), nil) {
			// DebugLog("WebID-TLS", "Found a public key in the profile.")
			for range g.All(keyT.Object, ns.rdf.Get("type"), ns.cert.Get(t)) {
				// DebugLog("WebID-TLS", "Trying to match modulus found in cert:")
				// DebugLog("WebID-TLS", n)
				for range g.All(keyT.Object, ns.cert.Get("modulus"), NewLiteral(n)) {
					goto matchModulus
				}
				for range g.All(keyT.Object, ns.cert.Get("modulus"), NewLiteralWithDatatype(n, NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))) {
					goto matchModulus
				}
			matchModulus:
				// DebugLog("WebID-TLS", "Found a matching modulus in the profile.")
				for range g.All(keyT.Object, ns.cert.Get("exponent"), NewLiteral(e)) {
					goto matchExponent
				}
				for range g.All(keyT.Object, ns.cert.Get("exponent"), NewLiteralWithDatatype(e, NewResource("http://www.w3.org/2001/XMLSchema#int"))) {
					goto matchExponent
				}
			matchExponent:
				// DebugLog("WebID-TLS", "Found a matching exponent in the profile.")
				// DebugLog("WebID-TLS", "Authenticated claim URI: "+claim)
				uri = claim
				webidL.Lock()
				pkeyURI[pkeyk] = uri
				webidL.Unlock()
				return
			}
			// DebugLog("WebID-TLS", "Could not find a certificate in the profile.")
		}
		// DebugLog("WebID-TLS", "Could not find a certificate public key in the profile.")
	}
	return
}

// WebIDFromCert returns subjectAltName string from x509 []byte
func WebIDFromCert(cert []byte) (string, error) {
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		return "", err
	}

	for _, x := range parsed.Extensions {
		if x.Id.Equal(subjectAltName) {
			v := asn1.RawValue{}
			_, err = asn1.Unmarshal(x.Value, &v)
			if err != nil {
				return "", err
			}
			return string(v.Bytes[2:]), nil
		}
	}
	return "", nil
}

// NewWebIDProfileWithKeys creates a WebID profile graph and corresponding keys
func NewWebIDProfileWithKeys(uri string) (*Graph, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}
	var account = webidAccount{
		URI:      uri,
		Modulus:  fmt.Sprintf("%x", priv.N),
		Exponent: fmt.Sprintf("%d", priv.E),
	}
	g := NewWebIDProfile(account)
	return g, priv, nil
}

// NewWebIDProfile creates a WebID profile graph based on account data
func NewWebIDProfile(account webidAccount) *Graph {

	profileURI := strings.Split(account.URI, "#")[0]
	userTerm := NewResource(account.URI)
	profileTerm := NewResource(profileURI)
	keyTerm := NewResource(profileURI + "#key")

	g := NewGraph(profileURI)
	g.AddTriple(profileTerm, ns.rdf.Get("type"), ns.foaf.Get("PersonalProfileDocument"))
	g.AddTriple(profileTerm, ns.foaf.Get("maker"), userTerm)
	g.AddTriple(profileTerm, ns.foaf.Get("primaryTopic"), userTerm)

	g.AddTriple(userTerm, ns.rdf.Get("type"), ns.foaf.Get("Person"))
	if len(account.Name) > 0 {
		g.AddTriple(profileTerm, ns.foaf.Get("title"), NewLiteral("WebID profile of "+account.Name))
		g.AddTriple(userTerm, ns.foaf.Get("fullname"), NewLiteral(account.Name))
	}
	if len(account.Email) > 0 {
		g.AddTriple(userTerm, ns.foaf.Get("mbox"), NewResource("mailto:"+account.Email))
	}
	if len(account.Img) > 0 {
		g.AddTriple(userTerm, ns.foaf.Get("img"), NewResource(account.Img))
	}
	g.AddTriple(userTerm, ns.cert.Get("key"), keyTerm)
	g.AddTriple(keyTerm, ns.rdf.Get("type"), ns.cert.Get("RSAPublicKey"))
	g.AddTriple(keyTerm, ns.cert.Get("modulus"), NewLiteralWithDatatype(account.Modulus, NewResource("http://www.w3.org/2001/XMLSchema#hexBinary")))
	g.AddTriple(keyTerm, ns.cert.Get("exponent"), NewLiteralWithDatatype(account.Exponent, NewResource("http://www.w3.org/2001/XMLSchema#int")))
	return g
}
