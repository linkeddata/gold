package gold

import (
	"strings"

	rdf "github.com/kierdavis/argo"
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

func (acl *WAC) Allow(mode string) bool {
	accessPath := acl.req.RequestURI
	accessUri := acl.req.BaseURI()

	aclPath := accessPath
	if strings.HasSuffix(aclPath, ".") {
		aclPath = aclPath[:len(aclPath)-1] + ACLSuffix
	} else if !strings.HasSuffix(aclPath, ACLSuffix) {
		aclPath += ACLSuffix
	}

	aclGraph := NewGraph(acl.Uri())
	aclGraph.ReadFile(acl.srv.root + aclPath)
	if aclGraph.Len() < 1 {
		return true
	}

	for _, i := range aclGraph.All(nil, ns["acl"].Get("mode"), ns["acl"].Get(mode)) {
		for _ = range aclGraph.All(i.Subject, ns["acl"].Get("accessTo"), rdf.NewResource(accessUri)) {
			for _ = range aclGraph.All(i.Subject, ns["acl"].Get("agent"), rdf.NewResource(acl.user)) {
				return true
			}
			for _ = range aclGraph.All(i.Subject, ns["acl"].Get("agentClass"), ns["foaf"].Get("Agent")) {
				return true
			}
		}
	}

	return false
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
