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

func (acl *WAC) Allow(mode string, path string) bool {
	accessType := "accessTo"
	p, err := PathInfo(path)
	if err != nil {
		return false
	}
	lvls := strings.Split(p.file, "/")

	for i := 0; i <= len(lvls); i++ {
		p, err := PathInfo(path)
		if err != nil {
			return false
		}

		aclGraph := NewGraph(p.aclUri)
		aclGraph.ReadFile(acl.srv.root + "/" + p.aclFile)
		if aclGraph.Len() > 0 {
			for _, i := range aclGraph.All(nil, ns.acl.Get("mode"), ns.acl.Get(mode)) {
				for _ = range aclGraph.All(i.Subject, ns.acl.Get(accessType), NewResource(p.uri)) {
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
			path = p.base + "/" + filepath.Dir(p.file) + "/"
		} else {
			if filepath.Dir(filepath.Dir(p.file)) == "." {
				path = p.base + "/"
			} else {
				path = p.base + "/" + filepath.Dir(filepath.Dir(p.file)) + "/"
			}
		}
	}
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
