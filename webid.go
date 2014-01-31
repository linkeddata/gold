package gold

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	rdf "github.com/kierdavis/argo"
	"sync"
)

var (
	subjectAltName = []int{2, 5, 29, 17}

	// cache
	mu      = new(sync.Mutex)
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

func WebIDTLSAuth(state *tls.ConnectionState) (uri string, err error) {
	uri = ""
	err = nil

	if len(state.PeerCertificates) > 0 {
		for _, x := range state.PeerCertificates[0].Extensions {
			if !x.Id.Equal(subjectAltName) {
				continue
			}
			if len(x.Value) < 5 {
				continue
			}
			claim := string(x.Value[4:])
			if len(claim) == 0 {
				continue
			}
			pkey := state.PeerCertificates[0].PublicKey
			t, n, e := pkeyTypeNE(pkey)
			if len(t) == 0 {
				continue
			}

			pkeyk := fmt.Sprint([]string{t, n, e})
			mu.Lock()
			uri = pkeyURI[pkeyk]
			mu.Unlock()
			if len(uri) > 0 {
				return
			}

			g := NewGraph(claim)
			g.Load(claim)
			for keyT := range g.Filter(g.Term(), ns["cert"].Get("key"), nil) {
				for _ = range g.Filter(keyT.Object, ns["rdf"].Get("type"), ns["cert"].Get(t)) {
					for _ = range g.Filter(keyT.Object, ns["cert"].Get("modulus"), rdf.NewLiteral(n)) {
						for _ = range g.Filter(keyT.Object, ns["cert"].Get("exponent"), rdf.NewLiteral(e)) {
							uri = g.URI()
							mu.Lock()
							pkeyURI[pkeyk] = uri
							mu.Unlock()
							return
						}
					}
				}
			}
		}
	}
	return
}
