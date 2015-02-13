package gold

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

type pathInfo struct {
	Obj      *url.URL
	URI      string
	Base     string
	Path     string
	Root     string
	File     string
	FileType string
	AclURI   string
	AclFile  string
	MetaURI  string
	MetaFile string
}

func (s *Server) pathInfo(path string) (*pathInfo, error) {
	res := &pathInfo{}

	if len(path) == 0 {
		return nil, errors.New("missing resource path")
	}

	// hack - if source URI contains "one%2b+%2btwo" then it is
	// normally decoded to "one+ +two", but Go parses it to
	// "one+++two", so we replace the plus with a blank space
	// strings.Replace(path, "+", "%20", -1)

	p, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	res.Root = s.Config.Root
	// include host and port if running in vhosts mode
	if s.Config.Vhosts {
		host, port, _ := net.SplitHostPort(p.Host)
		if len(host) == 0 {
			host = p.Host
		}
		if len(port) > 0 {
			host = host + ":" + port
		}
		res.Root = s.Config.Root + host + "/"
	}

	if strings.HasPrefix(p.Path, "/") && len(p.Path) > 0 {
		p.Path = strings.TrimLeft(p.Path, "/")
	} else if len(p.Path) == 0 {
		p.Path += "/"
	}

	// Add missing trailing slashes for dirs
	res.FileType, err = magic.TypeByFile(res.Root + p.Path)
	if err == nil {
		// add missing slash for dirs unless we're dealing with root
		if res.FileType == "inode/directory" && !strings.HasSuffix(p.Path, "/") && len(p.Path) > 1 {
			p.Path += "/"
		}
	}
	// hack: url.EncodeQuery() uses + instead of %20 to encode whitespaces in the path
	//p.Path = strings.Replace(p.Path, " ", "%20", -1)

	if len(p.Path) == 0 {
		res.URI = p.String() + "/"
	} else {
		res.URI = p.String()
	}
	res.Obj = p
	res.Base = p.Scheme + "://" + p.Host
	res.Path = p.Path
	res.File = p.Path

	if strings.HasSuffix(res.Path, ",acl") {
		res.AclURI = res.URI
		res.AclFile = res.Path
		res.MetaURI = res.URI
		res.MetaFile = res.Path
	} else if strings.HasSuffix(res.Path, ",meta") || strings.HasSuffix(res.Path, ",meta/") {
		res.AclURI = res.URI + ACLSuffix
		res.AclFile = res.Path + ACLSuffix
		res.MetaURI = res.URI
		res.MetaFile = res.Path
	} else {
		res.AclURI = res.URI + ACLSuffix
		res.AclFile = res.Path + ACLSuffix
		res.MetaURI = res.URI + METASuffix
		res.MetaFile = res.Path + METASuffix
	}

	if s.Config.Vhosts {
		res.File = res.Root + res.File
		res.AclFile = res.Root + res.AclFile
		res.MetaFile = res.Root + res.MetaFile
	} else if len(s.Config.Root) > 0 {
		res.File = s.Config.Root + res.File
		res.AclFile = s.Config.Root + res.AclFile
		res.MetaFile = s.Config.Root + res.MetaFile
	}

	return res, nil
}
