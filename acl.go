package gold

import (
	"path/filepath"
	"strings"
)

type WAC struct {
	req  *httpRequest
	srv  *Server
	user string
}

func NewWAC(req *httpRequest, srv *Server, user string) *WAC {
	return &WAC{req: req, srv: srv, user: user}
}

func (acl *WAC) allow(mode string, path string, request *httpRequest) bool {
	origin := request.Header.Get("Origin")
	accessType := "accessTo"
	p, err := PathInfo(path)
	if err != nil {
		return false
	}
	depth := strings.Split(p.Path, "/")

	for i := 0; i <= len(depth); i++ {
		p, err := PathInfo(path)
		if err != nil {
			return false
		}

		aclGraph := NewGraph(p.AclUri)
		aclGraph.ReadFile(acl.srv.root + "/" + p.AclFile)
		if aclGraph.Len() > 0 {
			for _, i := range aclGraph.All(nil, ns.acl.Get("mode"), ns.acl.Get(mode)) {
				for _ = range aclGraph.All(i.Subject, ns.acl.Get(accessType), NewResource(p.Uri)) {
					if len(origin) > 0 {
						for _ = range aclGraph.All(i.Subject, ns.acl.Get("origin"), NewResource(origin)) {
							goto allowOrigin
						}
						continue
					}
				allowOrigin:
					for _ = range aclGraph.All(i.Subject, ns.acl.Get("agent"), NewResource(acl.user)) {
						return true
					}
					for _ = range aclGraph.All(i.Subject, ns.acl.Get("agentClass"), ns.foaf.Get("Agent")) {
						return true
					}
				}
			}
			return false
		}

		accessType = "defaultForNew"

		if i == 0 {
			if strings.HasSuffix(p.Path, "/") {
				path = p.Base + "/" + filepath.Dir(filepath.Dir(p.Path)) + "/"
			} else {
				path = p.Base + "/" + filepath.Dir(p.Path) + "/"
			}
		} else {
			if len(p.Path) == 0 {
				break
			} else if filepath.Dir(filepath.Dir(p.Path)) == "." {
				path = p.Base + "/"
			} else {
				path = p.Base + "/" + filepath.Dir(filepath.Dir(p.Path)) + "/"
			}
		}
	}
	return true
}

func (acl *WAC) AllowRead(path string, request *httpRequest) bool {
	return acl.allow("Read", path, request)
}

func (acl *WAC) AllowWrite(path string, request *httpRequest) bool {
	return acl.allow("Write", path, request)
}

func (acl *WAC) AllowAppend(path string, request *httpRequest) bool {
	return acl.allow("Append", path, request)
}
