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
		return
	}

	if len(tls.PeerCertificates) > 0 {
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
				return
			}

			for _, keyT := range g.All(NewResource(claim), ns.cert.Get("key"), nil) {
				for _ = range g.All(keyT.Object, ns.rdf.Get("type"), ns.cert.Get(t)) {
					for _ = range g.All(keyT.Object, ns.cert.Get("modulus"), NewLiteral(n)) {
						for _ = range g.All(keyT.Object, ns.cert.Get("exponent"), NewLiteral(e)) {
							uri = claim
							webidL.Lock()
							pkeyURI[pkeyk] = uri
							webidL.Unlock()
							return
						}
					}
				}
			}
		}
	}

	return
}
