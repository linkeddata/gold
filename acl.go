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
	if len(req.Header.Get("On-Behalf-Of")) > 0 {
		delegator := debrack(req.Header.Get("On-Behalf-Of"))
		if VerifyDelegator(delegator, user) {
			DebugLog("WAC", "Request User ID (delegation): "+user)
			user = delegator
		}
	}
	return &WAC{req: req, srv: srv, user: user}
}

func (acl *WAC) allow(mode string, path string) bool {
	origin := acl.req.Header.Get("Origin")
	accessType := "accessTo"
	p, err := acl.srv.pathInfo(path)
	if err != nil {
		return false
	}
	depth := strings.Split(p.Path, "/")

	for i := 0; i < len(depth); i++ {
		p, err := acl.srv.pathInfo(path)
		if err != nil {
			return false
		}

		DebugLog("WAC", "Checking "+accessType+" <"+mode+"> to "+p.Uri+" for WebID: "+acl.user)
		DebugLog("WAC", "Looking for policies in "+p.AclFile)

		aclGraph := NewGraph(p.AclUri)
		aclGraph.ReadFile(p.AclFile)
		if aclGraph.Len() > 0 {
			DebugLog("WAC", "Found policies in "+p.AclFile)
			// TODO make it more elegant instead of duplicating code
			for _, i := range aclGraph.All(nil, ns.acl.Get("mode"), ns.acl.Get("Control")) {
				for _ = range aclGraph.All(i.Subject, ns.acl.Get(accessType), NewResource(p.Uri)) {
					for _ = range aclGraph.All(i.Subject, ns.acl.Get("owner"), NewResource(acl.user)) {
						DebugLog("WAC", mode+" access allowed (as owner) for: "+acl.user)
						return true
					}
					for _ = range aclGraph.All(i.Subject, ns.acl.Get("agent"), NewResource(acl.user)) {
						DebugLog("WAC", mode+" access allowed (as agent) for: "+acl.user)
						return true
					}
					for _, t := range aclGraph.All(i.Subject, ns.acl.Get("agentClass"), nil) {
						// check for foaf groups
						DebugLog("WAC", "Found agentClass policy")
						if t.Object.Equal(ns.foaf.Get("Agent")) {
							DebugLog("WAC", mode+" access allowed as FOAF Agent")
							return true
						} else {
							groupURI := debrack(t.Object.String())
							groupGraph := NewGraph(groupURI)
							groupGraph.LoadURI(groupURI)
							if groupGraph.Len() > 0 && groupGraph.One(t.Object, ns.rdf.Get("type"), ns.foaf.Get("Group")) != nil {
								for _ = range groupGraph.All(t.Object, ns.foaf.Get("member"), NewResource(acl.user)) {
									DebugLog("WAC", acl.user+" listed as a member of the group "+groupURI)
									return true
								}
							}
						}
					}
				}
			}
			for _, i := range aclGraph.All(nil, ns.acl.Get("mode"), ns.acl.Get(mode)) {
				DebugLog("WAC", "Found "+accessType+" policy for <"+mode+">")

				for _ = range aclGraph.All(i.Subject, ns.acl.Get(accessType), NewResource(p.Uri)) {
					origins := aclGraph.All(i.Subject, ns.acl.Get("origin"), nil)
					if len(origin) > 0 && len(origins) > 0 {
						DebugLog("WAC", "Origin set to: "+brack(origin))
						for _, o := range origins {
							if brack(origin) == o.Object.String() {
								DebugLog("WAC", "Found policy for origin: "+o.Object.String())
								goto allowOrigin
							}
						}
						continue
					} else {
						DebugLog("WAC", "No origin found, moving on")
					}
				allowOrigin:
					DebugLog("WAC", "In allowOrigin")
					for _ = range aclGraph.All(i.Subject, ns.acl.Get("owner"), NewResource(acl.user)) {
						DebugLog("WAC", mode+" access allowed (as owner) for: "+acl.user)
						return true
					}
					for _ = range aclGraph.All(i.Subject, ns.acl.Get("agent"), NewResource(acl.user)) {
						DebugLog("WAC", mode+" access allowed (as agent) for: "+acl.user)
						return true
					}
					for _, t := range aclGraph.All(i.Subject, ns.acl.Get("agentClass"), nil) {
						// check for foaf groups
						DebugLog("WAC", "Found agentClass policy")
						if t.Object.Equal(ns.foaf.Get("Agent")) {
							DebugLog("WAC", mode+" access allowed as FOAF Agent")
							return true
						} else {
							groupURI := debrack(t.Object.String())
							groupGraph := NewGraph(groupURI)
							groupGraph.LoadURI(groupURI)
							if groupGraph.Len() > 0 && groupGraph.One(t.Object, ns.rdf.Get("type"), ns.foaf.Get("Group")) != nil {
								for _ = range groupGraph.All(t.Object, ns.foaf.Get("member"), NewResource(acl.user)) {
									DebugLog("WAC", acl.user+" listed as a member of the group "+groupURI)
									return true
								}
							}
						}
					}
				}
			}
			DebugLog("WAC", mode+" access denied for: "+acl.user)
			return false
		}

		accessType = "defaultForNew"

		if i == 0 {
			if strings.HasSuffix(p.Path, "/") {
				if filepath.Dir(filepath.Dir(p.Path)) == "." {
					path = p.Base
				} else {
					path = p.Base + "/" + filepath.Dir(filepath.Dir(p.Path))
				}
			} else {
				path = p.Base + "/" + filepath.Dir(p.Path)
			}
		} else {
			if len(p.Path) == 0 {
				break
			} else if filepath.Dir(filepath.Dir(p.Path)) == "." {
				path = p.Base
			} else {
				path = p.Base + "/" + filepath.Dir(filepath.Dir(p.Path))
			}
		}

		path += "/"
	}
	DebugLog("WAC", "No ACL policies present - access allowed for: "+acl.user)
	return true
}

func (acl *WAC) AllowRead(path string) bool {
	return acl.allow("Read", path)
}

func (acl *WAC) AllowWrite(path string) bool {
	return acl.allow("Write", path)
}

func (acl *WAC) AllowAppend(path string) bool {
	return acl.allow("Append", path)
}

func VerifyDelegator(delegator string, delegatee string) bool {
	g := NewGraph(delegator)
	err := g.LoadURI(delegator)
	if err != nil {
		DebugLog("WAC", "Error loading graph for "+delegator)
	}

	for _, val := range g.All(NewResource(delegator), NewResource("http://www.w3.org/ns/auth/acl#delegatee"), nil) {
		if debrack(val.Object.String()) == delegatee {
			return true
		}
	}
	return false
}
