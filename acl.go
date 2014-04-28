package gold

import (
	"os"
	"path/filepath"
	"strings"
)

var (
	ACLSuffix = ",acl"
	ACLPath   = "/.acl/"
)

type WAC struct {
	req  *httpRequest
	srv  *Server
	user string
}

type Verdict struct {
	status bool
	err    error
}

func NewWAC(req *httpRequest, srv *Server, user string) *WAC {
	return &WAC{req: req, srv: srv, user: user}
}

func (acl *WAC) Check(path string, method string) *Verdict {
	ver := new(Verdict)
	ver.status = true
	return ver
}

func (acl *WAC) AllowRead(path string) *Verdict {
	if len(path) == 0 {
		// do something
	}

	return acl.Check(path, "Read")
}

func (acl *WAC) AllowWrite() bool {
	return true
}

func (acl *WAC) AllowAppend() bool {
	return true
}

func (acl *WAC) Uri(path string) string {
	return path + ACLSuffix
}

func (acl *WAC) Path(path string) string {
	p := ""
	isDir := false
	stat, err := os.Stat(path)
	if err != nil {
		// attempt to guess from pathURI
		if strings.HasSuffix(path, "/") {
			isDir = true
		}
	} else {
		if stat.IsDir() {
			isDir = true
		}
	}
	if isDir {
		p = path + ACLPath + ".ttl"
	} else {
		p = filepath.Dir(path) + ACLPath + filepath.Base(path)
	}

	return p
}
