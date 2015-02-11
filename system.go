package gold

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	_path "path"
	"strings"
)

type systemReturn struct {
	Status int
	Body   string
	Bytes  []byte
}

type accountRequest struct {
	Method      string
	AccountName string
}

type accountResponse struct {
	AccountName string `json:"accountName"`
	Available   bool   `json:"available"`
}

type statusResponse struct {
	Method   string          `json:"method"`
	Status   string          `json:"status"`
	FormURL  string          `json:"formURL"`
	LoginURL string          `json:"loginURL"`
	Response accountResponse `json:"response"`
}

// HandleSystem is a router for system specific APIs
func HandleSystem(w http.ResponseWriter, req *httpRequest, s *Server) systemReturn {
	if strings.Contains(req.BaseURI(), "accountStatus") {
		// unsupported yet when server is running on one host
		if s.vhosts == true {
			return accountStatus(w, req, s)
		}
	} else if strings.Contains(req.BaseURI(), "newAccount") {
		return newAccount(w, req, s)
	}
	return systemReturn{Status: 200}
}

func newAccount(w http.ResponseWriter, req *httpRequest, s *Server) systemReturn {
	resource, _ := s.pathInfo(req.BaseURI())

	port := ""
	if ServerPort != ":443" {
		DebugLog("System", "Found different port value: "+ServerPort)
		port = ServerPort
	}

	username := strings.ToLower(req.FormValue("username"))
	webidBase := resource.Base + "/" + username + "/"
	webidURL := webidBase + "profile/card"
	if s.vhosts == true {
		webidBase = "https://" + username + "." + resource.Root + port + "/"
		webidURL = webidBase + "profile/card"
	}
	webidURI := webidURL + "#me"
	resource, _ = s.pathInfo(webidURL)

	spkac := req.FormValue("spkac")

	// get public key from spkac
	pubKey, err := ParseSPKAC(spkac)
	if err != nil {
		DebugLog("System", "[newAccount] ParseSPKAC error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}
	rsaPub := pubKey.(*rsa.PublicKey)

	account := webidAccount{
		URI:      webidURI,
		Name:     req.FormValue("name"),
		Email:    req.FormValue("email"),
		Img:      req.FormValue("img"),
		Modulus:  fmt.Sprintf("%x", rsaPub.N),
		Exponent: fmt.Sprintf("%d", rsaPub.E),
	}

	DebugLog("System", "[newAccount] checking if account profile <"+resource.File+"> exists...")
	stat, err := os.Stat(resource.File)
	if err != nil {
		DebugLog("System", "Stat error: "+err.Error())
	}
	if stat != nil && !stat.IsDir() {
		DebugLog("System", "Found "+resource.File)
		return systemReturn{Status: 406, Body: "An account with the same name already exists."}
	}

	// create a new x509 cert based on the public key
	certName := account.Name + " [on " + resource.Obj.Host + "]"
	newSpkac, err := NewSPKACx509(webidURI, certName, spkac)
	if err != nil {
		DebugLog("System", "[newAccount] NewSPKACx509 error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}

	// Generate WebID profile graph for this account
	g := NewWebIDProfile(account)

	// create account space
	err = os.MkdirAll(_path.Dir(resource.File), 0755)
	if err != nil {
		DebugLog("Server", "[newAccount] MkdirAll error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}

	// open WebID profile file
	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		DebugLog("Server", "[newAccount] open profile error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}
	defer f.Close()

	// write WebID profile to disk
	err = g.WriteFile(f, "text/turtle")
	if err != nil {
		DebugLog("Server", "[newAccount] saving profile error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
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
		DebugLog("Server", "[newAccount] open profile acl error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}
	defer f.Close()

	// write profile acl to disk
	err = g.WriteFile(f, "text/turtle")
	if err != nil {
		DebugLog("Server", "[newAccount] saving profile acl error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}

	// Write default ACL for the whole account space
	// No one but the user is allowed access by default
	resource, _ = s.pathInfo(webidBase)
	aclTerm = NewResource(resource.AclURI + "#owner")
	g = NewGraph(resource.AclURI)
	g.AddTriple(aclTerm, ns.rdf.Get("type"), ns.acl.Get("Authorization"))
	g.AddTriple(aclTerm, ns.acl.Get("accessTo"), NewResource(resource.URI))
	g.AddTriple(aclTerm, ns.acl.Get("accessTo"), NewResource(resource.AclURI))
	g.AddTriple(aclTerm, ns.acl.Get("agent"), NewResource(webidURI))
	g.AddTriple(aclTerm, ns.acl.Get("defaultForNew"), NewResource(resource.URI))
	g.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Read"))
	g.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Write"))
	g.AddTriple(aclTerm, ns.acl.Get("mode"), ns.acl.Get("Control"))
	// open account acl file
	f, err = os.OpenFile(resource.AclFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		DebugLog("Server", "[newAccount] open account acl error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}
	defer f.Close()

	// write account acl to disk
	err = g.WriteFile(f, "text/turtle")
	if err != nil {
		DebugLog("Server", "[newAccount] saving account acl error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}

	// Send cert to the user for installation
	// Chrome requires direct download of certs; other browsers don't
	ua := req.Header.Get("User-Agent")
	if strings.Contains(ua, "Chrome") {
		w.Header().Set(HCType, "application/x-x509-user-cert; charset=utf-8")
		return systemReturn{Status: 200, Bytes: newSpkac}
	}
	// Prefer loading cert in iframe, to access onLoad events in the browser for the iframe
	body := `<iframe width="0" height="0" style="display: none;" src="data:application/x-x509-user-cert;base64,` + base64.StdEncoding.EncodeToString(newSpkac) + `"></iframe>`

	return systemReturn{Status: 200, Body: body}
}

// accountStatus implements a basic API to check whether a user account exists on the server
// Response object example:
// {
//	method:   "accountStatus",
//  status:   "success",
//  formuri:  "http://example.org/api/spkac",
//  response: {
//             accountName: "user",
//             available:   true
//            }
// }
func accountStatus(w http.ResponseWriter, req *httpRequest, s *Server) systemReturn {
	resource, _ := s.pathInfo(req.BaseURI())

	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		DebugLog("System", "[accountStatus] read body error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}
	if len(data) == 0 {
		DebugLog("System", "[accountStatus] empty request for accountStatus API")
		return systemReturn{Status: 500, Body: "Empty request for accountStatus API"}
	}
	var accReq accountRequest
	err = json.Unmarshal(data, &accReq)
	if err != nil {
		DebugLog("System", "[accountStatus] unmarshal error: "+err.Error())
		return systemReturn{Status: 500, Body: err.Error()}
	}
	accReq.AccountName = strings.ToLower(accReq.AccountName)

	w.Header().Set(HCType, "application/json")
	status := "success"
	accName := accReq.AccountName
	accURL := resource.Obj.Scheme + "://" + accName + "." + resource.Obj.Host + "/"
	isAvailable := true

	DebugLog("System", "[accountStatus] checking if account <"+accReq.AccountName+"> exists...")
	stat, err := os.Stat(s.root + accName + "." + resource.Root)
	if err != nil {
		DebugLog("System", "Stat error: "+err.Error())
	}
	if stat != nil && stat.IsDir() {
		DebugLog("System", "[accountStatus] found "+s.root+accName+"."+resource.Root)
		isAvailable = false
	}

	res := statusResponse{
		Method:   "accountStatus",
		Status:   status,
		FormURL:  resource.Base + "/" + SystemPrefix + "/newAccount",
		LoginURL: resource.Base,
		Response: accountResponse{
			AccountName: accURL,
			Available:   isAvailable,
		},
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		DebugLog("System", "[accountStatus] marshal error: "+err.Error())
	}
	return systemReturn{Status: 200, Body: string(jsonData)}
}
