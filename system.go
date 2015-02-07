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
	Formuri  string          `json:"formuri"`
	Response accountResponse `json:"response"`
}

// HandleSystem is a router for system specific APIs
func HandleSystem(w http.ResponseWriter, req *httpRequest, s *Server) (int, string) {
	if strings.Contains(req.BaseURI(), "accountStatus") {
		// unsupported yet when server is running on one host
		if s.vhosts == true {
			status, payload := accountStatus(w, req, s)
			return status, payload
		}
	} else if strings.Contains(req.BaseURI(), "newAccount") {
		status, payload := newAccount(w, req, s)
		return status, payload
	}
	return 200, ""
}

func newAccount(w http.ResponseWriter, req *httpRequest, s *Server) (int, string) {
	//@@TODO make sure not to overwrite an existing profile
	resource, _ := s.pathInfo(req.BaseURI())

	port := ""
	if ServerPort != ":443" || ServerPort != ":80" {
		port = ServerPort
	}

	username := strings.ToLower(req.FormValue("username"))
	webidPath := resource.Root + "/" + username + "/profile/"
	webidURI := resource.Base + "/" + username + "/profile/card#me"
	if s.vhosts == true {
		webidPath = s.root + username + "." + resource.Root + "/profile/"
		webidURI = "https://" + username + "." + resource.Root + port + "/profile/card#me"
	}
	webidFile := webidPath + "card"

	spkac := req.FormValue("spkac")

	account := webidAccount{
		URI:   webidURI,
		Name:  req.FormValue("name"),
		Email: req.FormValue("email"),
		Img:   req.FormValue("img"),
	}

	DebugLog("System", "[newAccount] checking if account profile <"+webidFile+"> exists...")
	stat, err := os.Stat(webidFile)
	if err != nil {
		DebugLog("System", "Stat error: "+err.Error())
	}
	if stat != nil && !stat.IsDir() {
		DebugLog("System", "Found "+webidFile)
		return 406, "An account with the same name already exists."
	}

	// create a new x509 cert based on the public key
	certName := account.Name + " [on " + username + "." + resource.Root + "]"
	newSpkac, err := NewSPKACx509(webidURI, certName, spkac)
	if err != nil {
		DebugLog("System", "[newAccount] NewSPKACx509 error: "+err.Error())
		return 500, err.Error()
	}

	// get public key from spkac
	pubKey, err := ParseSPKAC(spkac)
	if err != nil {
		DebugLog("System", "[newAccount] ParseSPKAC error: "+err.Error())
		return 500, err.Error()
	}
	rsaPub := pubKey.(*rsa.PublicKey)
	account.Modulus = fmt.Sprintf("%x", rsaPub.N)
	account.Exponent = fmt.Sprintf("%d", rsaPub.E)

	// Get WebID profile graph for this account
	g := NewWebIDProfile(account)

	// create account space
	err = os.MkdirAll(_path.Dir(webidPath), 0755)
	if err != nil {
		DebugLog("Server", "[newAccount] MkdirAll error: "+err.Error())
		return 500, err.Error()
	}

	// open WebID profile file
	f, err := os.OpenFile(webidFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		DebugLog("Server", "[newAccount] open profile error: "+err.Error())
		return 500, err.Error()
	}
	defer f.Close()

	// @@@ TODO @@@ set ACLs

	// write WebID profile to disk
	err = g.WriteFile(f, "text/turtle")
	if err != nil {
		DebugLog("Server", "[newAccount] saving profile error: "+err.Error())
		return 500, err.Error()
	}

	cert := base64.StdEncoding.EncodeToString(newSpkac)

	// Chrome access direct download of certs; other browsers don't
	ua := req.Header.Get("User-Agent")
	if strings.Contains(ua, "Chrome") {
		w.Header().Set(HCType, "application/x-x509-user-cert; charset=utf-8")
	} else {
		cert = `<iframe width="0" height="0" style="display: none;" src="data:application/x-x509-user-cert;base64,` + cert + `"></iframe>`
	}

	return 200, cert
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
func accountStatus(w http.ResponseWriter, req *httpRequest, s *Server) (int, string) {
	resource, _ := s.pathInfo(req.BaseURI())

	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		DebugLog("System", "[accountStatus] read body error: "+err.Error())
		return 500, err.Error()
	}
	if len(data) == 0 {
		DebugLog("System", "[accountStatus] empty request for accountStatus API")
		return 500, "Empty request for accountStatus API"
	}
	var accReq accountRequest
	err = json.Unmarshal(data, &accReq)
	if err != nil {
		DebugLog("System", "[accountStatus] unmarshal error: "+err.Error())
		return 500, err.Error()
	}
	accReq.AccountName = strings.ToLower(accReq.AccountName)

	w.Header().Set(HCType, "application/json")
	status := "success"
	accName := accReq.AccountName
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
		Method:  "accountStatus",
		Status:  status,
		Formuri: resource.Base + "/" + SystemPrefix + "/newAccount",
		Response: accountResponse{
			AccountName: accName,
			Available:   isAvailable,
		},
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		DebugLog("System", "[accountStatus] marshal error: "+err.Error())
	}
	return 200, string(jsonData)
}
