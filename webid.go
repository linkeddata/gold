package gold

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
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

// WebIDDigestAuth performs a digest authentication using WebID-RSA
func WebIDDigestAuth(req *httpRequest) (string, error) {
	if len(req.Header.Get("Authorization")) == 0 {
		return "", nil
	}

	authH, err := ParseDigestAuthorizationHeader(req.Header.Get("Authorization"))
	if err != nil {
		return "", err
	}

	if len(authH.Source) == 0 || authH.Source != req.BaseURI() {
		return "", errors.New("Bad source URI for auth token: " + authH.Source + " -- possible MITM attack!")
	}

	claim := sha1.Sum([]byte(authH.Source + authH.Username + authH.Nonce))
	signature, err := base64.StdEncoding.DecodeString(authH.Signature)
	if err != nil {
		return "", errors.New(err.Error() + " in " + authH.Signature)
	}

	if len(authH.Username) == 0 || len(claim) == 0 || len(signature) == 0 {
		return "", errors.New("No WebID and/or claim found in the Authorization header")
	}

	// fetch WebID to get pubKey
	if !strings.HasPrefix(authH.Username, "http") {
		return "", errors.New("Username is not a valid HTTP URI: " + authH.Username)
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
		return "", errors.New("Token expired for " + authH.Username)
	}
	if len(tValues["secret"]) == 0 {
		return "", errors.New("Missing secret from token (tempered with?)")
	}
	if tValues["secret"] != string(req.Server.cookieSalt) {
		return "", errors.New("Wrong secret value in client token!")
	}

	g := NewGraph(authH.Username)
	err = g.LoadURI(authH.Username)
	if err != nil {
		return "", err
	}

	req.debug.Println("Checking for public keys for user", authH.Username)
	for _, keyT := range g.All(NewResource(authH.Username), ns.cert.Get("key"), nil) {
		for range g.All(keyT.Object, ns.rdf.Get("type"), ns.cert.Get("RSAPublicKey")) {
			req.debug.Println("Found RSA key in user's profile", keyT.Object.String())
			for _, pubP := range g.All(keyT.Object, ns.cert.Get("pem"), nil) {
				keyP := term2C(pubP.Object).String()
				req.debug.Println("Found matching public key in user's profile", keyP[:10], "...", keyP[len(keyP)-10:len(keyP)])
				parser, err := ParseRSAPublicPEMKey([]byte(keyP))
				if err == nil {
					err = parser.Verify(claim[:], signature)
					if err == nil {
						return authH.Username, nil
					}
				}
				req.debug.Println("Unable to verify signature with key", keyP[:10], "...", keyP[len(keyP)-10:len(keyP)], "-- reason:", err)
			}
			// also loop through modulus/exp
			for _, pubN := range g.All(keyT.Object, ns.cert.Get("modulus"), nil) {
				keyN := term2C(pubN.Object).String()
				for _, pubE := range g.All(keyT.Object, ns.cert.Get("exponent"), nil) {
					keyE := term2C(pubE.Object).String()
					req.debug.Println("Found matching modulus and exponent in user's profile", keyN[:10], "...", keyN[len(keyN)-10:len(keyN)])
					parser, err := ParseRSAPublicKeyNE("RSAPublicKey", keyN, keyE)
					if err == nil {
						err = parser.Verify(claim[:], signature)
						if err == nil {
							return authH.Username, nil
						}
					}
					req.debug.Println("Unable to verify signature with key", keyN[:10], "...", keyN[len(keyN)-10:len(keyN)], "-- reason:", err)
				}
			}
		}
	}

	return "", err
}

// WebIDTLSAuth - performs WebID-TLS authentication
func WebIDTLSAuth(req *httpRequest) (uri string, err error) {
	tls := req.TLS
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
			san := ""
			for _, r := range string(v.Bytes[2:]) {
				if rune(r) == 65533 {
					san += ","
				} else if unicode.IsGraphic(rune(r)) {
					san += string(r)
				}
			}
			for _, sanURI := range strings.Split(san, ",") {
				sanURI = strings.TrimSpace(sanURI)
				if len(sanURI) == 0 {
					continue
				}
				if strings.HasPrefix(sanURI, "URI:") {
					claim = strings.TrimSpace(sanURI[4:])
					break
				} else if strings.HasPrefix(sanURI, "http") {
					claim = sanURI
					break
				}
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
				req.debug.Println("Found matching public modulus and exponent in user's profile")
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
