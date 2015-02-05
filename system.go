package gold

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	// "os"
	"strings"
)

type accountRequest struct {
	method      string
	accountName string
}

type accountResponse struct {
	accountName string
	available   bool
}

type statusResponse struct {
	method   string
	status   string
	formuri  string
	response accountResponse
}

// HandleSystem intercepts requests to ,system/ and routes them to the appropriate handler
func HandleSystem(w http.ResponseWriter, req *httpRequest, resource ldpath) *response {
	r := new(response)

	dataMime := req.Header.Get(HCType)
	dataMime = strings.Split(dataMime, ";")[0]

	if strings.Contains(resource.Path, "accountStatus") {
		r = accountStatus(w, req, resource, r)
	}
	return r
}

func spkac() {

}

// Response: {
//    		method:   "accountStatus",
//    		status:   "success",
//    		formuri:  "http://example.org/api/spkac",
//    		response: {
//                accountName: "user",
//                available:   true
//            }
// 		}
func accountStatus(w http.ResponseWriter, req *httpRequest, resource ldpath, r *response) *response {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		DebugLog("System", err.Error())
		r.respond(500, err)
	}
	var accReq accountRequest
	err = json.Unmarshal(data, &accReq)
	if err != nil {
		DebugLog("System", err.Error())
		r.respond(500, err)
	}

	w.Header().Set(HCType, "application/json")
	status := "success"
	accName := accReq.accountName
	isAvailable := true

	println(resource.Root)

	// stat, err := os.Stat(resource.Root)
	// if err != nil {
	// 	DebugLog("System", err.Error())
	// 	r.respond(500, err)
	// }
	// if stat.IsDir() {
	// 	isAvailable = false
	// }

	res := statusResponse{
		method:  "accountStatus",
		status:  status,
		formuri: resource.Base + "/" + SystemPrefix + "/spkac",
		response: accountResponse{
			accountName: accName,
			available:   isAvailable,
		},
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		DebugLog("System", err.Error())
	}
	return r.respond(200, jsonData)
}
