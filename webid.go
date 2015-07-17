package gold

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
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

func genCacheName(webid string) string {
	src := []byte(webid)
	// @@TODO add date/timestamp
	return base64.StdEncoding.EncodeToString(src)
}

// WebIDDigestAuth performs a digest authentication using WebID-RSA
func WebIDDigestAuth(req *httpRequest) (string, error) {
	if len(req.Header.Get("Authorization")) == 0 {
		return "", nil
	}

	authH, err := ParseDigestAuthorizationHeader(req.Header.Get("Authorization"))
	if err != nil {
		return "", err
	}

	source := authH.Source
	if len(source) == 0 || source != req.BaseURI() {
		return "", errors.New("Bad source of auth token, possible MITM attack!")
	}

	webid := authH.Username
	claim := source + authH.Username + authH.Nonce
	signature, err := base64.StdEncoding.DecodeString(authH.Signature)
	if err != nil {
		return "", err
	}

	if len(webid) == 0 || len(claim) == 0 || len(signature) == 0 {
		return "", errors.New("No WebID and/or claim found in the Authorization header")
	}

	// Decrypt and validate nonce from secure token
	tValues, err := ValidateSecureToken("WWW-Authenticate", authH.Nonce, req.Server)
	if err != nil {
		return "", err
	}
	v, err := strconv.ParseInt(tValues["valid"], 10, 64)
	if err != nil {
		return "", err
	}
	if time.Now().Local().Unix() > v {
		return "", errors.New("Token expired for " + webid)
	}
	if len(tValues["secret"]) == 0 {
		return "", errors.New("Missing secret from token (tempered with?)")
	}
	if tValues["secret"] != string(req.Server.cookieSalt) {
		return "", errors.New("Wrong secret value in client token!")
	}

	// fetch WebID to get pubKey
	g := NewGraph(webid)
	err = g.LoadURI(webid)
	if err != nil {
		return "", err
	}

	for _, keyT := range g.All(NewResource(webid), ns.cert.Get("key"), nil) {
		for range g.All(keyT.Object, ns.rdf.Get("type"), ns.cert.Get("RSAPublicKey")) {
			for _, pubP := range g.All(keyT.Object, ns.cert.Get("pem"), nil) {
				keyP := term2C(pubP.Object).String()
				// loop through all the PEM keys
				parser, err := ParseRSAPublicPEMKey([]byte(keyP))
				if err == nil {
					err = parser.Verify([]byte(claim), signature)
					if err == nil {
						return webid, nil
					}
				}
			}
			// also loop through modulus/exp
			for _, pubN := range g.All(keyT.Object, ns.cert.Get("modulus"), nil) {
				keyN := term2C(pubN.Object).String()
				for _, pubE := range g.All(keyT.Object, ns.cert.Get("exponent"), nil) {
					keyE := term2C(pubE.Object).String()
					// println(keyN, keyE)
					parser, err := ParseRSAPublicKeyNE("RSAPublicKey", keyN, keyE)
					if err == nil {
						err = parser.Verify([]byte(claim), signature)
						if err != nil {
							return "", err
						}
						return webid, nil
					}
				}
			}
		}
	}

	return "", err
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
		if len(claim) == 0 || claim[:4] != "http" {
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

		// pkey from client contains WebID claim

		g := NewGraph(claim)
		err = g.LoadURI(claim)
		if err != nil {
			return "", err
		}

		for _, keyT := range g.All(NewResource(claim), ns.cert.Get("key"), nil) {
			// found pkey in the profile
			for range g.All(keyT.Object, ns.rdf.Get("type"), ns.cert.Get(t)) {
				for range g.All(keyT.Object, ns.cert.Get("modulus"), NewLiteral(n)) {
					goto matchModulus
				}
				for range g.All(keyT.Object, ns.cert.Get("modulus"), NewLiteralWithDatatype(n, NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))) {
					goto matchModulus
				}
			matchModulus:
				// found a matching modulus in the profile
				for range g.All(keyT.Object, ns.cert.Get("exponent"), NewLiteral(e)) {
					goto matchExponent
				}
				for range g.All(keyT.Object, ns.cert.Get("exponent"), NewLiteralWithDatatype(e, NewResource("http://www.w3.org/2001/XMLSchema#int"))) {
					goto matchExponent
				}
			matchExponent:
				// found a matching exponent in the profile
				uri = claim
				webidL.Lock()
				pkeyURI[pkeyk] = uri
				webidL.Unlock()
				return
			}
			// could not find a certificate in the profile
		}
		// could not find a certificate pkey in the profile
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
func NewWebIDProfileWithKeys(uri string) (*Graph, *rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, nil, err
	}
	pub := &priv.PublicKey
	var account = webidAccount{
		URI:      uri,
		Modulus:  fmt.Sprintf("%x", pub.N),
		Exponent: fmt.Sprintf("%d", pub.E),
	}
	g := NewWebIDProfile(account)
	return g, priv, pub, nil
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
		g.AddTriple(profileTerm, ns.dct.Get("title"), NewLiteral("WebID profile of "+account.Name))
		g.AddTriple(userTerm, ns.foaf.Get("name"), NewLiteral(account.Name))
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
