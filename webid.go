package gold

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	rsaBits = 2048
)

type webidAccount struct {
	Root     string
	BaseURI  string
	Document string
	WebID    string
	PrefURI  string
	Name     string
	Email    string
	Img      string
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
		{Name: "prefs", Label: "Preferences workspace", Type: ""},
		{Name: "inbox", Label: "Inbox", Type: ""},
		{Name: "keys", Label: "Keys", Type: ""},
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

// AddPEMKey creates a PEM key graph
func AddPEMKey(uri string, key string, webid string, comment string) (string, error) {
	g := NewGraph(uri)
	userTerm := NewResource(webid)
	keyTerm := NewResource(uri + "#key")
	if len(comment) == 0 {
		comment = "Created  " + time.Now().Format(time.RFC822)
	}

	g.AddTriple(userTerm, ns.cert.Get("key"), keyTerm)
	g.AddTriple(keyTerm, ns.rdf.Get("type"), ns.cert.Get("RSAPublicKey"))
	g.AddTriple(keyTerm, ns.rdfs.Get("comment"), NewLiteral(comment))
	g.AddTriple(keyTerm, ns.cert.Get("pem"), NewLiteral(key))

	data, err := g.Serialize("text/turtle")
	if err != nil {
		return "", err
	}
	return data, nil
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
	g.AddTriple(userTerm, ns.space.Get("storage"), NewResource(account.BaseURI))
	g.AddTriple(userTerm, ns.space.Get("preferencesFile"), NewResource(account.PrefURI))
	g.AddTriple(userTerm, ns.st.Get("inbox"), NewResource(account.BaseURI+"inbox/"))
	g.AddTriple(userTerm, ns.st.Get("keys"), NewResource(account.BaseURI+"keys/"))

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
		if ws.Name != "Inbox" {
			pref.AddTriple(wsTerm, ns.rdf.Get("type"), ns.space.Get("Workspace"))
			if len(ws.Type) > 0 {
				pref.AddTriple(wsTerm, ns.rdf.Get("type"), ns.space.Get(ws.Type))
			}
			pref.AddTriple(wsTerm, ns.dct.Get("title"), NewLiteral(ws.Label))

			pref.AddTriple(NewResource(account.WebID), ns.space.Get("workspace"), wsTerm)
		}
	}

	resource, _ := req.pathInfo(account.PrefURI)
	// open account acl file
	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// write account acl to disk
	err = pref.WriteFile(f, "text/turtle")
	if err != nil {
		return err
	}

	return nil
}
