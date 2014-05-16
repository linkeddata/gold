package gold

import (
	"path/filepath"
	"strings"
)

var (
	ACLSuffix = ",acl"
)

type WAC struct {
	req  *httpRequest
	srv  *Server
	user string
}

func NewWAC(req *httpRequest, srv *Server, user string) *WAC {
	return &WAC{req: req, srv: srv, user: user}
}

func (acl *WAC) Allow(method string, path string) bool {
	aclPath := filepath.Join(acl.srv.root, path)
	if strings.HasSuffix(aclPath, ".") {
		aclPath = aclPath[:len(aclPath)-1] + ACLSuffix
	} else if !strings.HasSuffix(aclPath, ACLSuffix) {
		aclPath += ACLSuffix
	}

	// aclUri := filepath.Join(acl.req.BaseURI(), path)
	// if !strings.HasSuffix(aclUri, ACLSuffix) {
	// 	aclUri += ACLSuffix
	// }
	// log.Println(method, path)
	// log.Println(aclPath, aclUri)
	return true
}

func (acl *WAC) AllowRead(path string) bool {
	return acl.Allow("Read", path)
}

func (acl *WAC) AllowWrite(path string) bool {
	return acl.Allow("Write", path)
}

func (acl *WAC) AllowAppend(path string) bool {
	return acl.Allow("Append", path)
}

func (acl *WAC) Uri(path string) string {
	if strings.HasSuffix(path, ".") {
		path = path[:len(path)-1]
	}
	return path + ACLSuffix
}
