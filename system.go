package gold

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	_path "path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	Method   string          `json:"method"`
	Status   string          `json:"status"`
	FormURL  string          `json:"formURL"`
	LoginURL string          `json:"loginURL"`
	Response accountResponse `json:"response"`
}

type accountInformation struct {
	DiskUsed  string
	DiskLimit string
}

// HandleSystem is a router for system specific APIs
func HandleSystem(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	if strings.Contains(req.BaseURI(), "login") {
		loginPage(w, req, s)
		return SystemReturn{}
	} else if strings.Contains(req.BaseURI(), "accountStatus") {
		// unsupported yet when server is running on one host
		return accountStatus(w, req, s)
	} else if strings.Contains(req.Request.URL.Path, "newAccount") {
		return newAccount(w, req, s)
	} else if strings.Contains(req.Request.URL.Path, "newCert") {
		return newCert(w, req, s)
	} else if strings.Contains(req.Request.URL.Path, "accountInfo") {
		return accountInfo(w, req, s)
	} else if strings.Contains(req.Request.URL.Path, "accountRecovery") {
		return accountRecovery(w, req, s)
	}
	return SystemReturn{Status: 200}
}

func loginPage(w http.ResponseWriter, req *httpRequest, s *Server) {
	pathUri := strings.Split(req.RequestURI, SystemPrefix+"/login")[1]
	uri, err := url.Parse(req.Server.Config.SignInApp)
	if err != nil {
		s.debug.Println("Could not parse URL:", req.RequestURI, err.Error())
	}
	uri.Path = _path.Join(uri.Path, pathUri)
	req.Request.URL = uri
	req.Request.Host = uri.Host
	req.Request.RequestURI = uri.RequestURI()
	NewProxy().ServeHTTP(w, req.Request)
}

func accountRecovery(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	if len(req.FormValue("webid")) > 0 && strings.HasPrefix(req.FormValue("webid"), "http") {
		return sendRecoveryToken(w, req, s)
	} else if len(req.FormValue("token")) > 0 {
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
		return SystemReturn{Status: 500, Body: "Could not generate recovery token for " + webid + ", err: " + err.Error()}
	}
	// create recovery URL
	IP, _, _ := net.SplitHostPort(req.Request.RemoteAddr)
	link := resource.Base + "/" + SystemPrefix + "/accountRecovery?token=" + token
	to := []string{email}
	go s.sendRecoveryMail(resource.Obj.Host, IP, to, link)
	return SystemReturn{Status: 200, Body: "You should receive an email shortly, with further instructions."}
}

func validateRecoveryToken(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	token := req.FormValue("token")
	value := make(map[string]string)
	err := s.cookie.Decode("Recovery", token, &value)
	if err != nil {
		s.debug.Println("Decoding err: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	if len(value["valid"]) > 0 {
		v, err := strconv.ParseInt(value["valid"], 10, 64)
		if err != nil {
			s.debug.Println("Int parsing err: " + err.Error())
			return SystemReturn{Status: 500, Body: err.Error()}
		}

		if time.Now().Local().Unix() > v {
			s.debug.Println("Token expired!")
			return SystemReturn{Status: 498, Body: "Token expired!"}
		}
		// also set cookie now
		err = s.userCookieSet(w, value["webid"])
		if err != nil {
			s.debug.Println("Error setting new cookie: " + err.Error())
			return SystemReturn{Status: 500, Body: err.Error()}
		}
		return SystemReturn{Status: 200, Body: Apps["newCert"]}
	}
	return SystemReturn{Status: 499, Body: "Missing validity date for token."}
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
	resource, _ = req.pathInfo(webidURL)

	account := webidAccount{
		Root:     resource.Root,
		BaseURI:  resource.Base,
		Document: resource.File,
		WebID:    webidURI,
		PrefURI:  accountBase + "profile/prefs.ttl",
		Email:    req.FormValue("email"),
		Name:     req.FormValue("name"),
		Img:      req.FormValue("img"),
	}

	s.debug.Println("Checking if account profile <" + resource.File + "> exists...")
	stat, err := os.Stat(resource.File)
	if err != nil {
		s.debug.Println("Stat error: " + err.Error())
	}
	if stat != nil && !stat.IsDir() {
		s.debug.Println("Found " + resource.File)
		return SystemReturn{Status: 406, Body: "An account with the same name already exists."}
	}

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

	// Generate cert
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
		Method:   "accountStatus",
		Status:   status,
		FormURL:  resource.Obj.Scheme + "://" + req.Host + "/" + SystemPrefix + "/newAccount",
		LoginURL: accURL,
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

func accountInfo(w http.ResponseWriter, req *httpRequest, s *Server) SystemReturn {
	resource, _ := req.pathInfo(req.BaseURI())
	totalSize, err := DiskUsage(resource.Root)
	if err != nil {
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	data := accountInformation{
		DiskUsed:  fmt.Sprintf("%d", totalSize),
		DiskLimit: fmt.Sprintf("%d", s.Config.DiskLimit),
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		s.debug.Println("Marshal error: " + err.Error())
	}
	return SystemReturn{Status: 200, Body: string(jsonData)}
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
