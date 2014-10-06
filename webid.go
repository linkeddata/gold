package gold

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/asn1"
	"fmt"
	"sync"
)

var (
	subjectAltName = []int{2, 5, 29, 17}

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

func WebIDTLSAuth(tls *tls.ConnectionState) (uri string, err error) {
	claim := ""
	uri = ""
	err = nil

	if tls == nil || !tls.HandshakeComplete {
		DebugLog("WebID-TLS", "Not a TLS connection. TLS handshake failed")
		return
	}

	if len(tls.PeerCertificates) < 1 {
		DebugLog("WebID-TLS", "No client certificate found in the TLS request!")
		return
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
			claim = string(v.Bytes[2:])
		}
		if len(claim) == 0 {
			continue
		}

		pkey := tls.PeerCertificates[0].PublicKey
		t, n, e := pkeyTypeNE(pkey)
		if len(t) == 0 {
			continue
		}

		DebugLog("WebID-TLS", "Found public key from client containing WebID claim: "+claim)

		pkeyk := fmt.Sprint([]string{t, n, e})
		webidL.Lock()
		uri = pkeyURI[pkeyk]
		webidL.Unlock()
		if len(uri) > 0 {
			DebugLog("WebID-TLS", "Authenticated WebID:"+uri)
			return
		}

		g := NewGraph(claim)
		err = g.LoadURI(claim)
		if err != nil {
			DebugLog("WebID-TLS", err.Error())
			return
		}

		for _, keyT := range g.All(NewResource(claim), ns.cert.Get("key"), nil) {
			DebugLog("WebID-TLS", "Found a public key in the profile.")
			for _ = range g.All(keyT.Object, ns.rdf.Get("type"), ns.cert.Get(t)) {
				DebugLog("WebID-TLS", "Trying to match modulus found in cert:")
				DebugLog("WebID-TLS", n)
				for _ = range g.All(keyT.Object, ns.cert.Get("modulus"), NewLiteral(n)) {
					goto matchModulus
				}
				for _ = range g.All(keyT.Object, ns.cert.Get("modulus"), NewLiteralWithDatatype(n, NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))) {
					goto matchModulus
				}
			matchModulus:
				DebugLog("WebID-TLS", "Found a matching modulus in the profile.")
				for _ = range g.All(keyT.Object, ns.cert.Get("exponent"), NewLiteral(e)) {
					goto matchExponent
				}
				for _ = range g.All(keyT.Object, ns.cert.Get("exponent"), NewLiteralWithDatatype(e, NewResource("http://www.w3.org/2001/XMLSchema#int"))) {
					goto matchExponent
				}
			matchExponent:
				DebugLog("WebID-TLS", "Found a matching exponent in the profile.")
				DebugLog("WebID-TLS", "Authenticated claim URI: "+claim)
				uri = claim
				webidL.Lock()
				pkeyURI[pkeyk] = uri
				webidL.Unlock()
				return
			}
			DebugLog("WebID-TLS", "Could not find a certificate in the profile.")
		}
		DebugLog("WebID-TLS", "Could not find a certificate public key in the profile.")
	}
	return
}
