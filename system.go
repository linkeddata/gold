package gold

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
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

func HandleSystem(w http.ResponseWriter, req *httpRequest, vhosts bool, root string, resource ldpath) (int, string) {
	if strings.Contains(resource.Path, "accountStatus") {
		// unsupported yet when server is running on one host
		if vhosts == true {
			status, payload := accountStatus(w, req, root, resource)
			return status, payload
		}
	}
	return 200, ""
}

func spkac() {

}

// AccountStatus implements a basic API to check whether a user account exists on the server
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
func accountStatus(w http.ResponseWriter, req *httpRequest, root string, resource ldpath) (int, string) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		DebugLog("System", "Read body error: "+err.Error())
		return 500, err.Error()
	}
	if len(data) == 0 {
		DebugLog("System", "Empty request for accountStatus API")
		return 500, "Empty request for accountStatus API"
	}
	var accReq accountRequest
	err = json.Unmarshal(data, &accReq)
	if err != nil {
		DebugLog("System", "Unmarshal error: "+err.Error())
		return 500, err.Error()
	}

	w.Header().Set(HCType, "application/json")
	status := "success"
	accName := accReq.AccountName
	isAvailable := true

	DebugLog("System", "Checking if account <"+accReq.AccountName+"> exists...")
	stat, err := os.Stat(root + accName + "." + resource.Root)
	if err != nil {
		DebugLog("System", "Stat error: "+err.Error())
	}
	if stat != nil && stat.IsDir() {
		DebugLog("System", "Found "+root+accName+"."+resource.Root)
		isAvailable = false
	}

	res := statusResponse{
		Method:  "accountStatus",
		Status:  status,
		Formuri: resource.Base + "/" + SystemPrefix + "/spkac",
		Response: accountResponse{
			AccountName: accName,
			Available:   isAvailable,
		},
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		DebugLog("System", "Marshal error: "+err.Error())
	}
	return 200, string(jsonData)
}
