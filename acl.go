package gold

type WAC struct {
	req  *httpRequest
	srv  *Server
	user string
}

func NewWAC(req *httpRequest, srv *Server, user string) *WAC {
	return &WAC{req: req, srv: srv, user: user}
}

func (acl *WAC) Allow(mode string, path string) bool {
	p, err := getPathInfo(path)
	if err != nil {
		return false
	}

	aclGraph := NewGraph(p.aclUri)
	aclGraph.ReadFile(acl.srv.root + "/" + p.aclFile)
	if aclGraph.Len() < 1 {
		return true
	}

	for _, i := range aclGraph.All(nil, ns.acl.Get("mode"), ns.acl.Get(mode)) {
		for _ = range aclGraph.All(i.Subject, ns.acl.Get("accessTo"), NewResource(p.uri)) {
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

func (acl *WAC) AllowRead(path string) bool {
	return acl.Allow("Read", path)
}

func (acl *WAC) AllowWrite(path string) bool {
	return acl.Allow("Write", path)
}

func (acl *WAC) AllowAppend(path string) bool {
	return acl.Allow("Append", path)
}
