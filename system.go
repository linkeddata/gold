package gold

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	_path "path"
	"path/filepath"
	"strings"
	"time"

	"github.com/boltdb/bolt"
)

// SystemReturn is a generic HTTP response specific to system APIs
type SystemReturn struct {
	Status int
	Body   string
	Bytes  []byte
}

type accountRequest struct {
	Method      string
	AccountName string
}

type accountResponse struct {
	AccountURL string `json:"accountURL"`
	Available  bool   `json:"available"`
}

type statusResponse struct {
	Method    string          `json:"method"`
	Status    string          `json:"status"`
	FormURL   string          `json:"formURL"`
	LoginURL  string          `json:"loginURL"`
	LogoutURL string          `json:"logoutURL"`
	Response  accountResponse `json:"response"`
}

type accountInformation struct {
	DiskUsed  string
	DiskLimit string
}

// HandleSystem is a router for system specific APIs
func HandleSystem(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	if strings.HasSuffix(req.Request.URL.Path, "status") {
		// unsupported yet when server is running on one host
		return accountStatus(w, req, s)
	} else if strings.HasSuffix(req.Request.URL.Path, "new") {
		return newAccount(w, req, s)
	} else if strings.HasSuffix(req.Request.URL.Path, "cert") {
		return newCert(w, req, s)
	} else if strings.HasSuffix(req.Request.URL.Path, "login") {
		return logIn(w, req, s)
	} else if strings.HasSuffix(req.Request.URL.Path, "logout") {
		return logOut(w, req, s)
	} else if strings.HasSuffix(req.Request.URL.Path, "tokens") {
		return accountTokens(w, req, s)
	} else if strings.HasSuffix(req.Request.URL.Path, "recovery") {
		return accountRecovery(w, req, s)
	}
	return SystemReturn{Status: 200}
}

func logOut(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	s.userCookieDelete(w)
	return SystemReturn{Status: 200, Body: "You have been signed out!"}
}

func logIn(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	var passL string
	redirTo := req.FormValue("redirect")
	origin := req.FormValue("origin")

	s.debug.Println("Got login request. Optional params: ", redirTo, origin)

	// if cookie is set, just redirect
	if len(req.User) > 0 {
		values := map[string]string{
			"webid":  req.User,
			"origin": origin,
		}
		// refresh cookie
		err := s.userCookieSet(w, req.User)
		if err != nil {
			s.debug.Println("Error setting new cookie: " + err.Error())
			return SystemReturn{Status: 500, Body: err.Error()}
		}
		// redirect
		if len(redirTo) > 0 {
			loginRedirect(w, req, s, values, redirTo)
		}
		return SystemReturn{Status: 200, Body: LogoutTemplate(req.User)}
	}

	webid := req.FormValue("webid")
	passF := req.FormValue("password")

	if req.Method == "GET" {
		// try to guess WebID from account
		webid = req.getAccountWebID()
		return SystemReturn{Status: 200, Body: LoginTemplate(redirTo, origin, webid)}
	}

	if len(webid) == 0 && len(passF) == 0 {
		return SystemReturn{Status: 409, Body: "You must supply a valid WebID and password."}
	}
	resource, err := req.pathInfo(req.BaseURI())
	if err != nil {
		s.debug.Println("PathInfo error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	// try to fetch hashed password from root ,acl
	resource, _ = req.pathInfo(resource.Base)
	kb := NewGraph(resource.AclURI)
	kb.ReadFile(resource.AclFile)
	s.debug.Println("Looking for password in", resource.AclFile)
	// find the policy containing root acl
	for _, m := range kb.All(nil, ns.acl.Get("mode"), ns.acl.Get("Control")) {
		p := kb.One(m.Subject, ns.acl.Get("password"), nil)
		if p != nil && kb.One(m.Subject, ns.acl.Get("agent"), NewResource(webid)) != nil {
			passL = unquote(p.Object.String())
			break
		}
	}
	// exit if no pass
	if len(passL) == 0 {
		s.debug.Println("Access denied! Could not find a password for WebID: " + webid)
		return SystemReturn{Status: 403, Body: "Access denied! Could not find a password for WebID: " + webid}
	}

	// check if passwords match
	passF = saltedPassword(s.Config.Salt, passF)
	if passF != passL {
		s.debug.Println("Access denied! Bad WebID or password.")
		return SystemReturn{Status: 403, Body: "Access denied! Bad WebID or password."}
	}

	// auth OK
	// also set cookie now
	err = s.userCookieSet(w, webid)
	if err != nil {
		s.debug.Println("Error setting new cookie: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// handle redirect
	if len(redirTo) > 0 {
		values := map[string]string{
			"webid":  webid,
			"origin": origin,
		}
		loginRedirect(w, req, s, values, redirTo)
	}

	http.Redirect(w, req.Request, req.RequestURI, 301)
	return SystemReturn{Status: 200}
}

func loginRedirect(w http.ResponseWriter, req *httpRequest, s *Server, values map[string]string, redirTo string) SystemReturn {
	key := ""
	// try to get existing token
	key, err := s.getTokenByOrigin("Authorization", req.Host, values["origin"])
	if err != nil || len(key) == 0 {
		s.debug.Println("Could not find a token for origin:", values["origin"])
		key, err = s.newPersistedToken("Authorization", req.Host, values)
		if err != nil {
			s.debug.Println("Could not generate authorization token for " + values["webid"] + ", err: " + err.Error())
			return SystemReturn{Status: 500, Body: "Could not generate auth token for " + values["webid"] + ", err: " + err.Error()}
		}
	}
	s.debug.Println("Generated new token for", values["webid"], "->", key)
	redir, err := url.Parse(redirTo)
	if err != nil {
		return SystemReturn{Status: 400, Body: "Could not parse URL " + redirTo + ". Error: " + err.Error()}
	}
	q := redir.Query()
	q.Set("webid", values["webid"])
	q.Set("key", key)
	redir.RawQuery = q.Encode()
	s.debug.Println("Redirecting user to", redir.String())
	http.Redirect(w, req.Request, redir.String(), 301)
	return SystemReturn{Status: 200}
}

func accountRecovery(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	if len(req.FormValue("webid")) > 0 && strings.HasPrefix(req.FormValue("webid"), "http") {
		return sendRecoveryToken(w, req, s)
	} else if len(req.FormValue("token")) > 0 {
		// validate or issue new password
		return validateRecoveryToken(w, req, s)
	}
	// return default app with form
	return SystemReturn{Status: 200, Body: Apps["accountRecovery"]}
}

func sendRecoveryToken(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	webid := req.FormValue("webid")
	// exit if not a local WebID
	// log.Println("Host:" + req.Header.Get("Host"))
	resource, err := req.pathInfo(req.BaseURI())
	if err != nil {
		s.debug.Println("PathInfo error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	// try to fetch recovery email from root ,acl
	resource, _ = req.pathInfo(resource.Base)
	email := ""
	kb := NewGraph(resource.AclURI)
	kb.ReadFile(resource.AclFile)
	// find the policy containing root acl
	for range kb.All(nil, ns.acl.Get("accessTo"), NewResource(resource.AclURI)) {
		for _, t := range kb.All(nil, ns.acl.Get("agent"), nil) {
			email = debrack(t.Object.String())
			if strings.HasPrefix(email, "mailto:") {
				email = strings.TrimPrefix(email, "mailto:")
				break
			}
		}
	}
	// exit if no email
	if len(email) == 0 {
		s.debug.Println("Access denied! Could not find a recovery email for WebID: " + webid)
		return SystemReturn{Status: 403, Body: "Access denied! Could not find a recovery email for WebID: " + webid}
	}
	values := map[string]string{
		"webid": webid,
	}
	// set validity for now + 5 mins
	t := time.Duration(s.Config.TokenAge) * time.Minute
	token, err := NewSecureToken("Recovery", values, t, s)
	if err != nil {
		s.debug.Println("Could not generate recovery token for " + webid + ", err: " + err.Error())
		return SystemReturn{Status: 400, Body: "Could not generate recovery token for " + webid + ", err: " + err.Error()}
	}
	// create recovery URL
	IP, _, _ := net.SplitHostPort(req.Request.RemoteAddr)
	link := resource.Base + "/" + SystemPrefix + "/recovery?token=" + encodeQuery(token)
	// Setup message
	params := make(map[string]string)
	params["{{.To}}"] = email
	params["{{.IP}}"] = IP
	params["{{.Host}}"] = resource.Obj.Host
	params["{{.From}}"] = s.Config.SMTPConfig.Addr
	params["{{.Link}}"] = link
	go s.sendRecoveryMail(params)
	return SystemReturn{Status: 200, Body: "You should receive an email shortly with further instructions."}
}

func validateRecoveryToken(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	token, err := decodeQuery(req.FormValue("token"))
	if err != nil {
		s.debug.Println("Decode query err: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	value := make(map[string]string)
	err = s.cookie.Decode("Recovery", token, &value)
	if err != nil {
		s.debug.Println("Decoding err: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	if len(value["valid"]) == 0 {
		return SystemReturn{Status: 499, Body: "Missing validity date for token."}
	}
	err = IsTokenDateValid(value["valid"])
	if err != nil {
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	// also set cookie now
	webid := value["webid"]
	err = s.userCookieSet(w, webid)
	if err != nil {
		s.debug.Println("Error setting new cookie: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	pass := req.FormValue("password")
	verif := req.FormValue("verifypass")
	if len(pass) > 0 && len(verif) > 0 {
		if pass != verif {
			// passwords don't match,
			return SystemReturn{Status: 200, Body: NewPassTemplate(token, "Passwords do not match!")}
		}
		// save new password
		resource, _ := req.pathInfo(req.BaseURI())
		accountBase := resource.Base + "/"
		resource, _ = req.pathInfo(accountBase)

		g := NewGraph(resource.AclURI)
		g.ReadFile(resource.AclFile)
		// find the policy containing root acl
		for _, m := range g.All(nil, ns.acl.Get("mode"), ns.acl.Get("Control")) {
			p := g.One(m.Subject, ns.acl.Get("agent"), NewResource(webid))
			if p != nil {
				passT := g.One(nil, ns.acl.Get("password"), nil)
				// remove old password
				if passT != nil {
					g.Remove(passT)
				}
			}
			// add new password
			g.AddTriple(m.Subject, ns.acl.Get("password"), NewLiteral(saltedPassword(s.Config.Salt, pass)))

			// write account acl to disk
			// open account acl file
			f, err := os.OpenFile(resource.AclFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				s.debug.Println("Could not open file to save new password. Error: " + err.Error())
				return SystemReturn{Status: 500, Body: err.Error()}
			}
			defer f.Close()
			err = g.WriteFile(f, "text/turtle")
			if err != nil {
				s.debug.Println("Could not save account acl file with new password. Error: " + err.Error())
				return SystemReturn{Status: 500, Body: err.Error()}
			}
			// All set
			return SystemReturn{Status: 200, Body: "Password saved!"}
			break
		}
	}

	return SystemReturn{Status: 200, Body: NewPassTemplate(token, "")}
}

func newAccount(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	resource, _ := req.pathInfo(req.BaseURI())
	host, port, _ := net.SplitHostPort(req.Host)
	if len(host) == 0 {
		host = req.Host
	}
	if len(port) > 0 {
		port = ":" + port
	}

	accountBase := resource.Base + "/"

	username := strings.ToLower(req.FormValue("username"))
	if !strings.HasPrefix(host, username) {
		accountBase = resource.Base + "/" + username + "/"
		if s.Config.Vhosts == true {
			accountBase = "https://" + username + "." + host + port + "/"
		}
	}

	webidURL := accountBase + "profile/card"
	webidURI := webidURL + "#me"
	resource, _ = req.pathInfo(accountBase)

	account := webidAccount{
		Root:          resource.Root,
		BaseURI:       resource.Base,
		Document:      resource.File,
		WebID:         webidURI,
		Agent:         s.Config.Agent,
		PrefURI:       accountBase + "Preferences/prefs.ttl",
		PubTypeIndex:  accountBase + "Preferences/pubTypeIndex.ttl",
		PrivTypeIndex: accountBase + "Preferences/privTypeIndex.ttl",
		Email:         req.FormValue("email"),
		Name:          req.FormValue("name"),
		Img:           req.FormValue("img"),
	}
	if len(s.Config.ProxyTemplate) > 0 {
		account.ProxyURI = accountBase + ",proxy?uri="
	}
	if len(s.Config.QueryTemplate) > 0 {
		account.QueryURI = accountBase + ",query"
	}

	s.debug.Println("Checking if account profile <" + resource.File + "> exists...")
	stat, err := os.Stat(resource.File)
	if err != nil {
		s.debug.Println("Stat error: " + err.Error())
	}
	if stat != nil && stat.IsDir() {
		s.debug.Println("Found " + resource.File)
		return SystemReturn{Status: 406, Body: "An account with the same name already exists."}
	}

	resource, _ = req.pathInfo(webidURL)

	// create account space
	err = os.MkdirAll(_path.Dir(resource.File), 0755)
	if err != nil {
		s.debug.Println("MkdirAll error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// open WebID profile file
	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		s.debug.Println("Open profile error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	defer f.Close()

	// Generate WebID profile graph for this account
	g := NewWebIDProfile(account)

	// write WebID profile to disk
	err = g.WriteFile(f, "text/turtle")
	if err != nil {
		s.debug.Println("Saving profile error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Write ACL for the profile
	aclTerm := NewResource(resource.AclURI + "#owner")
	g = NewGraph(resource.AclURI)
	g.AddTriple(aclTerm, ns.rdf.Get("type"), ns.acl.Get("Authorization"))
	g.AddTriple(aclTerm, ns.acl.Get("accessTo"), NewResource(webidURL))
	g.AddTriple(aclTerm, ns.acl.Get("accessTo"), NewResource(resource.AclURI))
	g.AddTriple(aclTerm, ns.acl.Get("agent"), NewResource(webidURI))
	g.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Read"))
	g.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Write"))
	g.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Control"))
	readAllTerm := NewResource(resource.AclURI + "#readall")
	g.AddTriple(readAllTerm, ns.rdf.Get("type"), ns.acl.Get("Authorization"))
	g.AddTriple(readAllTerm, ns.acl.Get("accessTo"), NewResource(webidURL))
	g.AddTriple(readAllTerm, ns.acl.Get("agentClass"), ns.foaf.Get("Agent"))
	g.AddTriple(readAllTerm, ns.acl.Get("mode"), ns.acl.Get("Read"))
	// open profile acl file
	f, err = os.OpenFile(resource.AclFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		s.debug.Println("Open profile acl error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	defer f.Close()

	// write profile acl to disk
	err = g.WriteFile(f, "text/turtle")
	if err != nil {
		s.debug.Println("Saving profile acl error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Link from root meta file to the WebID
	err = req.LinkToWebID(account)
	if err != nil {
		s.debug.Println("Error setting up workspaces: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Create workspaces and preferencesFile
	err = req.AddWorkspaces(account, g)
	if err != nil {
		s.debug.Println("Error setting up workspaces: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Write default ACL for the whole account space
	// No one but the user is allowed access by default
	resource, _ = req.pathInfo(accountBase)
	aclTerm = NewResource(resource.AclURI + "#owner")
	g = NewGraph(resource.AclURI)
	g.AddTriple(aclTerm, ns.rdf.Get("type"), ns.acl.Get("Authorization"))
	g.AddTriple(aclTerm, ns.acl.Get("accessTo"), NewResource(resource.URI))
	g.AddTriple(aclTerm, ns.acl.Get("accessTo"), NewResource(resource.AclURI))
	g.AddTriple(aclTerm, ns.acl.Get("agent"), NewResource(webidURI))
	if len(req.FormValue("password")) > 0 {
		g.AddTriple(aclTerm, ns.acl.Get("password"), NewLiteral(saltedPassword(s.Config.Salt, req.FormValue("password"))))
	}
	if len(req.FormValue("email")) > 0 {
		g.AddTriple(aclTerm, ns.acl.Get("agent"), NewResource("mailto:"+req.FormValue("email")))
	}
	g.AddTriple(aclTerm, ns.acl.Get("defaultForNew"), NewResource(resource.URI))
	g.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Read"))
	g.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Write"))
	g.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Control"))
	// open account acl file
	f, err = os.OpenFile(resource.AclFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		s.debug.Println("Create account acl error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	defer f.Close()

	// write account acl to disk
	err = g.WriteFile(f, "text/turtle")
	if err != nil {
		s.debug.Println("Saving account acl error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Authenticate the user (set cookie)
	err = s.userCookieSet(w, webidURI)
	if err != nil {
		s.debug.Println("Error setting new cookie: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	w.Header().Set("User", webidURI)

	// Send welcome email
	if len(req.FormValue("email")) > 0 {
		// Setup message
		params := make(map[string]string)
		params["{{.To}}"] = req.FormValue("email")
		params["{{.From}}"] = s.Config.SMTPConfig.Addr
		params["{{.Name}}"] = account.Name
		params["{{.Host}}"] = resource.Obj.Host
		params["{{.Account}}"] = account.BaseURI
		params["{{.WebID}}"] = account.WebID
		go s.sendWelcomeMail(params)
	}

	// Generate cert
	// TODO to be deprecated soon
	spkac := req.FormValue("spkac")

	if len(spkac) > 0 {
		// create a new x509 cert based on the SPKAC public key
		certName := account.Name + " [on " + resource.Obj.Host + "]"
		newSpkac, err := NewSPKACx509(webidURI, certName, spkac)
		if err != nil {
			s.debug.Println("NewSPKACx509 error: " + err.Error())
			return SystemReturn{Status: 500, Body: err.Error()}
		}

		pubKey, err := ParseSPKAC(spkac)
		if err != nil {
			s.debug.Println("ParseSPKAC error: " + err.Error())
		}
		rsaPub := pubKey.(*rsa.PublicKey)
		mod := fmt.Sprintf("%x", rsaPub.N)
		exp := fmt.Sprintf("%d", rsaPub.E)
		err = req.AddCertKeys(webidURI, mod, exp)
		if err != nil {
			s.debug.Println("Couldn't add cert keys to profile: " + err.Error())
		}

		ua := req.Header.Get("User-Agent")
		if strings.Contains(ua, "Chrome") {
			w.Header().Set(HCType, "application/x-x509-user-cert; charset=utf-8")
			return SystemReturn{Status: 200, Bytes: newSpkac}
		}
		// Prefer loading cert in iframe, to access onLoad events in the browser for the iframe
		body := `<iframe width="0" height="0" style="display: none;" src="data:application/x-x509-user-cert;base64,` + base64.StdEncoding.EncodeToString(newSpkac) + `"></iframe>`

		return SystemReturn{Status: 200, Body: body}
	}
	return SystemReturn{Status: 200, Body: ""}
}

func newCert(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	resource, _ := req.pathInfo(req.BaseURI())

	name := req.FormValue("name")
	webidURI := req.FormValue("webid")
	spkac := req.FormValue("spkac")

	if len(webidURI) > 0 && len(spkac) > 0 {
		// create a new x509 cert based on the SPKAC public key
		certName := name + " [on " + resource.Obj.Host + "]"
		newSpkac, err := NewSPKACx509(webidURI, certName, spkac)
		if err != nil {
			s.debug.Println("NewSPKACx509 error: " + err.Error())
			return SystemReturn{Status: 500, Body: err.Error()}
		}
		s.debug.Println("Generated new cert for " + webidURI)

		// Append cert to profile if it's the case
		loggedUser := w.Header().Get("User")
		s.debug.Println("Checking if request is authenticated: " + loggedUser)
		if len(loggedUser) > 0 && loggedUser == webidURI && strings.HasPrefix(webidURI, resource.Base) {
			acl := NewWAC(req, s, w, loggedUser, "")
			aclStatus, err := acl.AllowWrite(strings.Split(webidURI, "#")[0])
			if aclStatus > 200 || err != nil {
				return SystemReturn{Status: aclStatus, Body: err.Error()}
			}

			pubKey, err := ParseSPKAC(spkac)
			if err != nil {
				s.debug.Println("ParseSPKAC error: " + err.Error())
				return SystemReturn{Status: 500, Body: err.Error()}
			}
			rsaPub := pubKey.(*rsa.PublicKey)
			mod := fmt.Sprintf("%x", rsaPub.N)
			exp := fmt.Sprintf("%d", rsaPub.E)
			err = req.AddCertKeys(webidURI, mod, exp)
			if err != nil {
				s.debug.Println("Couldn't add cert keys to profile: " + err.Error())
				return SystemReturn{Status: 500, Body: err.Error()}
			}
			s.debug.Println("Also added cert public key to " + webidURI)
		} else {
			s.debug.Println("Not authenticated / local user: " + loggedUser + " != " + webidURI + " on " + resource.Base)
		}

		s.debug.Println("Done issuing new cert for " + webidURI)

		ua := req.Header.Get("User-Agent")
		if strings.Contains(ua, "Chrome") {
			w.Header().Set(HCType, "application/x-x509-user-cert; charset=utf-8")
			return SystemReturn{Status: 200, Bytes: newSpkac}
		}
		// Prefer loading cert in iframe, to access onLoad events in the browser for the iframe
		body := `<iframe width="0" height="0" style="display: none;" src="data:application/x-x509-user-cert;base64,` + base64.StdEncoding.EncodeToString(newSpkac) + `"></iframe>`

		return SystemReturn{Status: 200, Body: body}
	} else if strings.Contains(req.Header.Get("Accept"), "text/html") {
		return SystemReturn{Status: 200, Body: Apps["newCert"]}
	}
	return SystemReturn{Status: 500, Body: "Your request could not be processed. Either no WebID or no SPKAC value was provided."}
}

// accountStatus implements a basic API to check whether a user account exists on the server
// Response object example:
// {
//	method:   "accountStatus",
//  status:   "success",
//  formURL:  "https://example.org/,system/spkac",
//  loginURL: "https://example.org/,system/login/",
//  response: {
//             accountURL: "user",
//             available:   true
//            }
// }
// @@TODO treat exceptions
func accountStatus(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	resource, _ := req.pathInfo(req.BaseURI())
	host, port, _ := net.SplitHostPort(req.Host)
	if len(host) == 0 {
		host = req.Host
	}
	if len(port) > 0 {
		port = ":" + port
	}

	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		s.debug.Println("Read body error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	if len(data) == 0 {
		s.debug.Println("Empty request for accountStatus API")
		return SystemReturn{Status: 500, Body: "Empty request for accountStatus API"}
	}
	var accReq accountRequest
	err = json.Unmarshal(data, &accReq)
	if err != nil {
		s.debug.Println("Unmarshal error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	accReq.AccountName = strings.ToLower(accReq.AccountName)

	w.Header().Set(HCType, "application/json")
	status := "success"
	accName := accReq.AccountName
	accURL := resource.Base + "/" + accName + "/"
	if s.Config.Vhosts {
		accURL = resource.Obj.Scheme + "://" + accName + "." + host + port + "/"
	}
	isAvailable := true
	resource, _ = req.pathInfo(accURL)

	s.debug.Println("Checking if account <" + accReq.AccountName + "> exists...")
	stat, err := os.Stat(resource.File)
	if err != nil {
		s.debug.Println("Stat error: " + err.Error())
	}
	if stat != nil && stat.IsDir() {
		s.debug.Println("Found " + s.Config.DataRoot + accName + "." + resource.Root)
		isAvailable = false
	}

	res := statusResponse{
		Method:    "status",
		Status:    status,
		FormURL:   resource.Obj.Scheme + "://" + req.Host + "/" + SystemPrefix + "/new",
		LoginURL:  accURL + SystemPrefix + "/login",
		LogoutURL: accURL + SystemPrefix + "/logout",
		Response: accountResponse{
			AccountURL: accURL,
			Available:  isAvailable,
		},
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		s.debug.Println("Marshal error: " + err.Error())
	}
	return SystemReturn{Status: 200, Body: string(jsonData)}
}

func accountTokens(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	if len(req.User) == 0 {
		return SystemReturn{Status: 401, Body: UnauthorizedTemplate(req.FormValue("redirect"), "")}
	}
	if !req.IsOwner {
		return SystemReturn{Status: 403, Body: "You are not allowed to view this page"}
	}

	tokensHtml := "<div>"

	if len(req.FormValue("revokeAuthz")) > 0 {
		delStatus := "<p style=\"color: green;\">Successfully revoked token!</p>"
		err := s.deletePersistedToken("Authorization", req.Host, req.FormValue("revokeAuthz"))
		if err != nil {
			delStatus = "<p>Could not revoke token. Error: " + err.Error() + "</p>"
		}
		tokensHtml += delStatus
	}

	tokens, err := s.getTokensByType("Authorization", req.Host)
	tokensHtml += "<h2>Authorization tokens for applications</h2>\n"
	tokensHtml += "<div>"
	if err == nil {
		for token, values := range tokens {
			tokensHtml += "<p>Token: " + string(token) + "<br>\n"
			tokensHtml += "Application: <strong>" + values["origin"] + "</strong>"
			tokensHtml += " <a href=\"" + req.BaseURI() + "?revokeAuthz=" + encodeQuery(token) + "\">Revoke</a></p>\n"
		}
		tokensHtml += "</ul>\n"
		if len(tokens) == 0 {
			tokensHtml += "No authorization tokens found."
		}
	}

	tokensHtml += "</div>"

	return SystemReturn{Status: 200, Body: TokensTemplate(tokensHtml)}
}

// DiskUsage returns the total size occupied by dir and contents
func DiskUsage(dirPath string) (int64, error) {
	var totalSize int64
	walkpath := func(path string, f os.FileInfo, err error) error {
		if err == nil && f != nil {
			totalSize += f.Size()
		}
		return err
	}
	err := filepath.Walk(dirPath, walkpath)
	return totalSize, err
}

func (s *Server) StartBolt() error {
	var err error
	s.BoltDB, err = bolt.Open(s.Config.BoltPath, 0644, nil)
	if err != nil {
		return err
	}
	return nil
}

// NewToken saves an API token to the bolt db. It returns the API token and a possible error
func (s *Server) newPersistedToken(tokenType, host string, values map[string]string) (string, error) {
	var token string
	if len(tokenType) == 0 || len(host) == 0 {
		return token, errors.New("Can't retrieve token from db. Missing values for token or host.")
	}
	// bucket(host) -> bucket(type) -> values
	err := s.BoltDB.Update(func(tx *bolt.Tx) error {
		userBucket, err := tx.CreateBucketIfNotExists([]byte(host))
		if err != nil {
			return err
		}
		bucket, err := userBucket.CreateBucketIfNotExists([]byte(tokenType))
		id, _ := bucket.NextSequence()
		values["id"] = fmt.Sprintf("%d", id)
		// set validity if not alreay set
		if len(values["valid"]) == 0 {
			// age times the duration of 6 month
			values["valid"] = fmt.Sprintf("%d",
				time.Now().Add(time.Duration(s.Config.TokenAge)*time.Hour*5040).Unix())
		}
		// marshal values to JSON
		tokenJson, err := json.Marshal(values)
		if err != nil {
			return err
		}
		token = fmt.Sprintf("%x", sha256.Sum256(tokenJson))
		err = bucket.Put([]byte(token), tokenJson)
		if err != nil {
			return err
		}

		return nil
	})

	return token, err
}

func (s *Server) getPersistedToken(tokenType, host, token string) (map[string]string, error) {
	tokenValues := map[string]string{}
	if len(tokenType) == 0 || len(host) == 0 || len(token) == 0 {
		return tokenValues, errors.New("Can't retrieve token from db. tokenType, host and token value are requrired.")
	}
	err := s.BoltDB.View(func(tx *bolt.Tx) error {
		userBucket := tx.Bucket([]byte(host))
		if userBucket == nil {
			return errors.New(host + " bucket not found!")
		}
		bucket := userBucket.Bucket([]byte(tokenType))
		if bucket == nil {
			return errors.New(tokenType + " bucket not found!")
		}

		// unmarshal
		b := bucket.Get([]byte(token))
		err := json.Unmarshal(b, &tokenValues)
		return err
	})
	return tokenValues, err
}

func (s *Server) getTokenByOrigin(tokenType, host, origin string) (string, error) {
	token := ""
	if len(tokenType) == 0 || len(host) == 0 || len(origin) == 0 {
		return token, errors.New("Can't retrieve token from db. tokenType, host and token value are requrired.")
	}
	s.debug.Println("Checking existing tokens for host:", host, "and origin:", origin)
	err := s.BoltDB.View(func(tx *bolt.Tx) error {
		userBucket := tx.Bucket([]byte(host))
		if userBucket == nil {
			return errors.New(host + " bucket not found!")
		}
		bucket := userBucket.Bucket([]byte(tokenType))
		if bucket == nil {
			return errors.New(tokenType + " bucket not found!")
		}

		// unmarshal
		c := bucket.Cursor()

		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			key := string(k)
			values, err := s.getPersistedToken(tokenType, host, key)
			if err == nil && values["origin"] == origin {
				token = key
				break
			}
		}

		return nil
	})
	return token, err
}

func (s *Server) deletePersistedToken(tokenType, host, token string) error {
	if len(tokenType) == 0 || len(host) == 0 || len(token) == 0 {
		return errors.New("Can't retrieve token from db. tokenType, host and token value are requrired.")
	}
	err := s.BoltDB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(host)).Bucket([]byte(tokenType)).Delete([]byte(token))
	})
	return err
}

func (s *Server) getTokensByType(tokenType, host string) (map[string]map[string]string, error) {
	tokens := make(map[string]map[string]string)
	err := s.BoltDB.View(func(tx *bolt.Tx) error {
		// Assume bucket exists and has keys
		b := tx.Bucket([]byte(host))
		if b == nil {
			return errors.New("No bucket for host " + host)
		}
		ba := b.Bucket([]byte(tokenType))
		if ba == nil {
			return errors.New("No bucket for type " + tokenType)
		}

		c := ba.Cursor()

		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			key := string(k)
			token, err := s.getPersistedToken(tokenType, host, key)
			if err == nil {
				tokens[key] = token
			}
		}
		return nil
	})
	return tokens, err
}
