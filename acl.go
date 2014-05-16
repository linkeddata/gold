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

func NewWAC(req *httpRequest, srv *Server, user string) *WAC {
	return &WAC{req: req, srv: srv, user: user}
}

func (acl *WAC) Allow(method string, path string) bool {
	// log.Println(path)
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
