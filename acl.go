package gold

import (
	// "log"
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

func (acl *WAC) Allow(method string) bool {
	accessPath := acl.req.RequestURI
	aclPath := accessPath
	if strings.HasSuffix(aclPath, ".") {
		aclPath = aclPath[:len(aclPath)-1] + ACLSuffix
	} else if !strings.HasSuffix(aclPath, ACLSuffix) {
		aclPath += ACLSuffix
	}

	// log.Println(method, accessPath, aclPath, acl.Uri())
	return true
}

func (acl *WAC) AllowRead() bool {
	return acl.Allow("Read")
}

func (acl *WAC) AllowWrite() bool {
	return acl.Allow("Write")
}

func (acl *WAC) AllowAppend() bool {
	return acl.Allow("Append")
}

func (acl *WAC) Uri() string {
	uri := acl.req.BaseURI()
	if !strings.HasSuffix(uri, ACLSuffix) {
		uri += ACLSuffix
	}
	return uri
}
