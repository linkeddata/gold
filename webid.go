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
	"os"
	_path "path"
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
	Root          string
	BaseURI       string
	Document      string
	WebID         string
	PrefURI       string
	PubTypeIndex  string
	PrivTypeIndex string
	Name          string
	Email         string
	Agent         string
	ProxyURI      string
	QueryURI      string
	Img           string
}

type workspace struct {
	Name  string
	Label string
	Type  string
}

var (
	subjectAltName = []int{2, 5, 29, 17}

	notBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)

	workspaces = []workspace{
		{Name: "Preferences", Label: "Preferences workspace", Type: ""},
		{Name: "Applications", Label: "Applications workspace", Type: "PreferencesWorkspace"},
		{Name: "Inbox", Label: "Inbox", Type: ""},
	}

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
		return "", errors.New("No WebID and/or claim found in the Authorization header.\n" + req.Header.Get("Authorization"))
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

// AddProfileKeys creates a WebID profile graph and corresponding keys
func AddProfileKeys(uri string, g *Graph) (*Graph, *rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, nil, err
	}
	pub := &priv.PublicKey

	profileURI := strings.Split(uri, "#")[0]
	userTerm := NewResource(uri)
	keyTerm := NewResource(profileURI + "#key")

	g.AddTriple(userTerm, ns.cert.Get("key"), keyTerm)
	g.AddTriple(keyTerm, ns.rdf.Get("type"), ns.cert.Get("RSAPublicKey"))
	g.AddTriple(keyTerm, ns.dct.Get("title"), NewLiteral("Created  "+time.Now().Format(time.RFC822)))
	g.AddTriple(keyTerm, ns.cert.Get("modulus"), NewLiteralWithDatatype(fmt.Sprintf("%x", pub.N), NewResource("http://www.w3.org/2001/XMLSchema#hexBinary")))
	g.AddTriple(keyTerm, ns.cert.Get("exponent"), NewLiteralWithDatatype(fmt.Sprintf("%d", pub.E), NewResource("http://www.w3.org/2001/XMLSchema#int")))

	return g, priv, pub, nil
}

// AddCertKeys adds the modulus and exponent values to the profile document
func (req *httpRequest) AddCertKeys(uri string, mod string, exp string) error {
	uuid := NewUUID()
	uuid = uuid[:4]

	profileURI := strings.Split(uri, "#")[0]
	userTerm := NewResource(uri)
	keyTerm := NewResource(profileURI + "#key" + uuid)

	resource, _ := req.pathInfo(profileURI)

	g := NewGraph(profileURI)
	g.ReadFile(resource.File)
	g.AddTriple(userTerm, ns.cert.Get("key"), keyTerm)
	g.AddTriple(keyTerm, ns.rdf.Get("type"), ns.cert.Get("RSAPublicKey"))
	g.AddTriple(keyTerm, ns.rdfs.Get("label"), NewLiteral("Created "+time.Now().Format(time.RFC822)+" on "+resource.Obj.Host))
	g.AddTriple(keyTerm, ns.cert.Get("modulus"), NewLiteralWithDatatype(mod, NewResource("http://www.w3.org/2001/XMLSchema#hexBinary")))
	g.AddTriple(keyTerm, ns.cert.Get("exponent"), NewLiteralWithDatatype(exp, NewResource("http://www.w3.org/2001/XMLSchema#int")))

	// open account acl file
	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// write account acl to disk
	err = g.WriteFile(f, "text/turtle")
	if err != nil {
		return err
	}

	return nil
}

// NewWebIDProfile creates a WebID profile graph based on account data
func NewWebIDProfile(account webidAccount) *Graph {
	profileURI := strings.Split(account.WebID, "#")[0]
	userTerm := NewResource(account.WebID)
	profileTerm := NewResource(profileURI)

	g := NewGraph(profileURI)
	g.AddTriple(profileTerm, ns.rdf.Get("type"), ns.foaf.Get("PersonalProfileDocument"))
	g.AddTriple(profileTerm, ns.foaf.Get("maker"), userTerm)
	g.AddTriple(profileTerm, ns.foaf.Get("primaryTopic"), userTerm)

	g.AddTriple(userTerm, ns.rdf.Get("type"), ns.foaf.Get("Person"))
	if len(account.Name) > 0 {
		g.AddTriple(profileTerm, ns.dct.Get("title"), NewLiteral("WebID profile of "+account.Name))
		g.AddTriple(userTerm, ns.foaf.Get("name"), NewLiteral(account.Name))
	}
	if len(account.Img) > 0 {
		g.AddTriple(userTerm, ns.foaf.Get("img"), NewResource(account.Img))
	}
	if len(account.Agent) > 0 {
		g.AddTriple(userTerm, ns.acl.Get("delegates"), NewResource(account.Agent))
	}
	g.AddTriple(userTerm, ns.space.Get("storage"), NewResource(account.BaseURI+"/"))
	g.AddTriple(userTerm, ns.space.Get("preferencesFile"), NewResource(account.PrefURI))
	g.AddTriple(userTerm, ns.st.Get("privateTypeIndex"), NewResource(account.PrivTypeIndex))
	g.AddTriple(userTerm, ns.st.Get("publicTypeIndex"), NewResource(account.PubTypeIndex))
	g.AddTriple(userTerm, ns.ldp.Get("inbox"), NewResource(account.BaseURI+"/Inbox/"))
	g.AddTriple(userTerm, ns.st.Get("timeline"), NewResource(account.BaseURI+"/Timeline/"))

	// add proxy and query endpoints
	if len(account.ProxyURI) > 0 {
		g.AddTriple(userTerm, ns.st.Get("proxyTemplate"), NewResource(account.ProxyURI))
	}
	if len(account.QueryURI) > 0 {
		g.AddTriple(userTerm, ns.st.Get("queryEndpoint"), NewResource(account.QueryURI))
	}

	return g
}

// LinkToWebID links the account URI (root container) to the WebID that owns the space
func (req *httpRequest) LinkToWebID(account webidAccount) error {
	resource, _ := req.pathInfo(account.BaseURI + "/")

	g := NewGraph(resource.URI)
	g.AddTriple(NewResource(account.WebID), ns.st.Get("account"), NewResource(resource.URI))

	// open account root meta file
	f, err := os.OpenFile(resource.MetaFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// write account meta file to disk
	err = g.WriteFile(f, "text/turtle")
	if err != nil {
		return err
	}

	return nil
}

func (req *httpRequest) getAccountWebID() string {
	resource, err := req.pathInfo(req.BaseURI())
	if err == nil {
		resource, _ = req.pathInfo(resource.Base)
		g := NewGraph(resource.MetaURI)
		g.ReadFile(resource.MetaFile)
		if g.Len() >= 1 {
			webid := g.One(nil, ns.st.Get("account"), NewResource(resource.MetaURI))
			if webid != nil {
				return debrack(webid.Subject.String())
			}
		}
	}

	return ""
}

// AddWorkspaces creates all the necessary workspaces corresponding to a new account
func (req *httpRequest) AddWorkspaces(account webidAccount, g *Graph) error {
	pref := NewGraph(account.PrefURI)
	prefTerm := NewResource(account.PrefURI)
	pref.AddTriple(prefTerm, ns.rdf.Get("type"), ns.space.Get("ConfigurationFile"))
	pref.AddTriple(prefTerm, ns.dct.Get("title"), NewLiteral("Preferences file"))

	pref.AddTriple(NewResource(account.WebID), ns.space.Get("preferencesFile"), NewResource(account.PrefURI))
	pref.AddTriple(NewResource(account.WebID), ns.rdf.Get("type"), ns.foaf.Get("Person"))

	for _, ws := range workspaces {
		resource, _ := req.pathInfo(account.BaseURI + "/" + ws.Name + "/")
		err := os.MkdirAll(resource.File, 0755)
		if err != nil {
			return err
		}

		// Write ACLs
		// No one but the user is allowed access by default
		aclTerm := NewResource(resource.AclURI + "#owner")
		wsTerm := NewResource(resource.URI)
		a := NewGraph(resource.AclURI)
		a.AddTriple(aclTerm, ns.rdf.Get("type"), ns.acl.Get("Authorization"))
		a.AddTriple(aclTerm, ns.acl.Get("accessTo"), wsTerm)
		a.AddTriple(aclTerm, ns.acl.Get("accessTo"), NewResource(resource.AclURI))
		a.AddTriple(aclTerm, ns.acl.Get("agent"), NewResource(account.WebID))
		if len(req.FormValue("email")) > 0 {
			a.AddTriple(aclTerm, ns.acl.Get("agent"), NewResource("mailto:"+account.Email))
		}
		a.AddTriple(aclTerm, ns.acl.Get("defaultForNew"), wsTerm)
		a.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Read"))
		a.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Write"))
		a.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Control"))
		if ws.Type == "PublicWorkspace" {
			readAllTerm := NewResource(resource.AclURI + "#readall")
			a.AddTriple(readAllTerm, ns.rdf.Get("type"), ns.acl.Get("Authorization"))
			a.AddTriple(readAllTerm, ns.acl.Get("accessTo"), wsTerm)
			a.AddTriple(readAllTerm, ns.acl.Get("agentClass"), ns.foaf.Get("Agent"))
			a.AddTriple(readAllTerm, ns.acl.Get("mode"), ns.acl.Get("Read"))
		}
		// Special case for Inbox (append only)
		if ws.Name == "Inbox" {
			appendAllTerm := NewResource(resource.AclURI + "#apendall")
			a.AddTriple(appendAllTerm, ns.rdf.Get("type"), ns.acl.Get("Authorization"))
			a.AddTriple(appendAllTerm, ns.acl.Get("accessTo"), wsTerm)
			a.AddTriple(appendAllTerm, ns.acl.Get("agentClass"), ns.foaf.Get("Agent"))
			a.AddTriple(appendAllTerm, ns.acl.Get("mode"), ns.acl.Get("Append"))
		}

		// open account acl file
		f, err := os.OpenFile(resource.AclFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()

		// write account acl to disk
		err = a.WriteFile(f, "text/turtle")
		if err != nil {
			return err
		}

		// Append workspace URL to the preferencesFile
		//if ws.Name != "Inbox" || ws.Name != "Timeline" { <- this assertion is always true ...
		pref.AddTriple(wsTerm, ns.rdf.Get("type"), ns.space.Get("Workspace"))
		if len(ws.Type) > 0 {
			pref.AddTriple(wsTerm, ns.rdf.Get("type"), ns.space.Get(ws.Type))
		}
		pref.AddTriple(wsTerm, ns.dct.Get("title"), NewLiteral(ws.Label))

		pref.AddTriple(NewResource(account.WebID), ns.space.Get("workspace"), wsTerm)
		//}
	}

	resource, _ := req.pathInfo(account.PrefURI)
	err := os.MkdirAll(_path.Dir(resource.File), 0755)
	if err != nil {
		return err
	}
	// open account acl file
	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	// write account acl to disk
	err = pref.WriteFile(f, "text/turtle")
	if err != nil {
		return err
	}
	f.Close()

	// write the typeIndex
	createTypeIndex(req, "ListedDocument", account.PubTypeIndex)
	createTypeIndex(req, "UnlistedDocument", account.PrivTypeIndex)

	return nil
}

func createTypeIndex(req *httpRequest, indexType, url string) error {
	typeIndex := NewGraph(url)
	typeIndex.AddTriple(NewResource(url), ns.rdf.Get("type"), ns.st.Get("TypeIndex"))
	typeIndex.AddTriple(NewResource(url), ns.rdf.Get("type"), ns.st.Get(indexType))

	resource, _ := req.pathInfo(url)
	err := os.MkdirAll(_path.Dir(resource.File), 0755)
	if err != nil {
		return err
	}
	// open account acl file
	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// write account acl to disk
	err = typeIndex.WriteFile(f, "text/turtle")
	return err
}
