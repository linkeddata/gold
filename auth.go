package gold

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// DigestAuthentication structure
type DigestAuthentication struct {
	Type, Source, Webid, KeyURL, Realm, Nonce, URI, QOP, NC, CNonce, Response, Opaque, Algorithm string
}

// DigestAuthorization structure
type DigestAuthorization struct {
	Type, Source, Webid, KeyURL, Nonce, Signature string
}

func (req *httpRequest) authn(w http.ResponseWriter) string {
	user, err := req.userCookie()
	if err != nil {
		req.Server.debug.Println("userCookie error:", err)
	}
	if len(user) > 0 {
		req.Server.debug.Println("Cookie auth OK for User: " + user)
		return user
	}

	if len(req.Header.Get("Authorization")) > 0 {
		user, err = WebIDDigestAuth(req)
		if err != nil {
			req.Server.debug.Println("WebID-RSA auth error:", err)
		}
		if len(user) > 0 {
			req.Server.debug.Println("WebID-RSA auth OK for User: " + user)
			return user
		}
	}

	user, err = WebIDTLSAuth(req)
	if err != nil {
		req.Server.debug.Println("WebID-TLS error:", err)
	}
	if len(user) > 0 {
		req.Server.debug.Println("WebID-TLS auth OK for User: " + user)
		req.Server.userCookieSet(w, user)
		return user
	}

	user = ""
	req.Server.debug.Println("Unauthenticated User")
	return user
}

func (req *httpRequest) userCookie() (string, error) {
	value := make(map[string]string)
	cookie, err := req.Cookie("Session")
	if err == nil {
		err = req.Server.cookie.Decode("Session", cookie.Value, &value)
		if err == nil {
			return value["user"], nil
		}
	}
	return "", err
}

func (srv *Server) userCookieSet(w http.ResponseWriter, user string) error {
	value := map[string]string{
		"user": user,
	}

	encoded, err := srv.cookie.Encode("Session", value)
	if err != nil {
		return err
	}
	t := time.Duration(srv.Config.CookieAge) * time.Hour
	cookieCfg := &http.Cookie{
		Expires: time.Now().Add(t),
		Name:    "Session",
		Path:    "/",
		Value:   encoded,
		Secure:  true,
	}
	http.SetCookie(w, cookieCfg)
	return nil
}

func (srv *Server) userCookieDelete(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "Session",
		Value:  "deleted",
		Path:   "/",
		MaxAge: -1,
	})
}

// ParseDigestAuthenticateHeader parses an Authenticate header and returns a DigestAuthentication object
func ParseDigestAuthenticateHeader(header string) (*DigestAuthentication, error) {
	auth := DigestAuthentication{}

	if len(header) == 0 {
		return &auth, errors.New("Cannot parse WWW-Authenticate header: no header present")
	}

	opts := make(map[string]string)
	parts := strings.SplitN(header, " ", 2)
	opts["type"] = parts[0]
	parts = strings.Split(parts[1], ",")

	for _, part := range parts {
		vals := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := vals[0]
		val := strings.Replace(vals[1], "\"", "", -1)
		opts[key] = val
	}

	auth = DigestAuthentication{
		opts["type"],
		opts["source"],
		opts["webid"],
		opts["keyurl"],
		opts["realm"],
		opts["nonce"],
		opts["uri"],
		opts["qop"],
		opts["nc"],
		opts["qnonce"],
		opts["response"],
		opts["opaque"],
		opts["algorithm"],
	}
	return &auth, nil
}

// ParseDigestAuthorizationHeader parses an Authorization header and returns a DigestAuthorization object
func ParseDigestAuthorizationHeader(header string) (*DigestAuthorization, error) {
	auth := DigestAuthorization{}

	if len(header) == 0 {
		return &auth, errors.New("Cannot parse Authorization header: no header present")
	}

	opts := make(map[string]string)
	parts := strings.SplitN(header, " ", 2)
	opts["type"] = parts[0]
	parts = strings.Split(parts[1], ",")

	for _, part := range parts {
		vals := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := vals[0]
		val := strings.Replace(vals[1], "\"", "", -1)
		opts[key] = val
	}

	auth = DigestAuthorization{
		opts["type"],
		opts["source"],
		opts["webid"],
		opts["keyurl"],
		opts["nonce"],
		opts["sig"],
	}
	return &auth, nil
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

	claim := sha256.Sum256([]byte(authH.Source + authH.Webid + authH.KeyURL + authH.Nonce))
	signature, err := base64.StdEncoding.DecodeString(authH.Signature)
	if err != nil {
		return "", errors.New(err.Error() + " in " + authH.Signature)
	}

	// Sanity checks
	if len(authH.Webid) == 0 || len(authH.KeyURL) == 0 || len(claim) == 0 || len(signature) == 0 {
		return "", errors.New("Incomplete Authorization header")
	}
	if !strings.HasPrefix(authH.Webid, "http") {
		return "", errors.New("WebID is not a valid HTTP URI: " + authH.Webid)
	}
	if !strings.HasPrefix(authH.KeyURL, "http") {
		return "", errors.New("Key URL is not a valid HTTP URIL: " + authH.KeyURL)
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
		return "", errors.New("Token expired for " + authH.Webid)
	}
	if len(tValues["secret"]) == 0 {
		return "", errors.New("Missing secret from token (tempered with?)")
	}
	if tValues["secret"] != string(req.Server.cookieSalt) {
		return "", errors.New("Wrong secret value in client token!")
	}

	// Fetch WebID to get key location
	g := NewGraph(authH.Webid)
	err = g.LoadURI(authH.Webid)
	if err != nil {
		return "", err
	}

	// go through each key location store
	req.debug.Println("Checking for public keys for user", authH.Webid)
	for _, keyT := range g.All(NewResource(authH.Webid), ns.st.Get("keys"), nil) {
		keyURL := term2C(keyT.Object).String()
		if strings.HasPrefix(authH.KeyURL, keyURL) {
			gk := NewGraph(authH.KeyURL)
			err = gk.LoadURI(authH.KeyURL)
			if err != nil {
				return "", err
			}
			for range gk.All(nil, ns.rdf.Get("type"), ns.cert.Get("RSAPublicKey")) {
				req.debug.Println("Found RSA key in user's profile", keyT.Object.String())
				for _, pubP := range gk.All(nil, ns.cert.Get("pem"), nil) {
					keyP := term2C(pubP.Object).String()
					req.debug.Println("Found matching public key in user's profile")
					parser, err := ParseRSAPublicPEMKey([]byte(keyP))
					if err != nil {
						req.debug.Println("Unable to parse public PEM key", "-- reason:", err)
						continue
					}
					err = parser.Verify(claim[:], signature)
					if err != nil {
						req.debug.Println("Unable to verify signature with key", authH.KeyURL, "-- reason:", err)
						continue
					}
					return authH.Webid, nil
				}
				// also loop through modulus/exp in case we didn't find a PEM key
				for _, pubN := range gk.All(keyT.Object, ns.cert.Get("modulus"), nil) {
					keyN := term2C(pubN.Object).String()
					for _, pubE := range gk.All(keyT.Object, ns.cert.Get("exponent"), nil) {
						keyE := term2C(pubE.Object).String()
						req.debug.Println("Found matching modulus and exponent in user's profile", keyN[:10], "...", keyN[len(keyN)-10:len(keyN)])
						parser, err := ParseRSAPublicKeyNE("RSAPublicKey", keyN, keyE)
						if err == nil {
							err = parser.Verify(claim[:], signature)
							if err == nil {
								return authH.Webid, nil
							}
						}
						req.debug.Println("Unable to verify signature with key", keyN[:10], "...", keyN[len(keyN)-10:len(keyN)], "-- reason:", err)
					}
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

// NewSecureToken generates a signed token to be used during account recovery
func NewSecureToken(tokenType string, values map[string]string, duration time.Duration, s *Server) (string, error) {
	valid := time.Now().Add(duration).Unix()
	values["valid"] = fmt.Sprintf("%d", valid)
	token, err := s.cookie.Encode(tokenType, values)
	if err != nil {
		s.debug.Println("Error encoding new token: " + err.Error())
		return "", err
	}
	return token, nil
}

// ValidateSecureToken returns the values of a secure cookie
func ValidateSecureToken(tokenType string, token string, s *Server) (map[string]string, error) {
	values := make(map[string]string)
	err := s.cookie.Decode(tokenType, token, &values)
	if err != nil {
		s.debug.Println("Secure token decoding error: " + err.Error())
		return values, err
	}

	return values, nil
}

// Store token
func StoreSecureToken(token string) error {
	if len(token) == 0 {
		return errors.New("No token provided")
	}
	return nil
}

// Read token
func ReadSecureToken(token string) error {
	if len(token) == 0 {
		return errors.New("No token provided")
	}
	return nil
}
