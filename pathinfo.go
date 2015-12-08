package gold

import (
	"errors"
	"net"
	"net/url"
	"os"
	_path "path"
	"path/filepath"
	"strings"
	"time"
)

type pathInfo struct {
	Obj       *url.URL
	URI       string
	Base      string
	Path      string
	Root      string
	File      string
	FileType  string
	ParentURI string
	AclURI    string
	AclFile   string
	MetaURI   string
	MetaFile  string
	Extension string
	MaybeRDF  bool
	IsDir     bool
	Exists    bool
	ModTime   time.Time
	Size      int64
}

func (req *httpRequest) pathInfo(path string) (*pathInfo, error) {
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

	res.Base = p.Scheme + "://" + p.Host
	res.Root = req.Server.Config.DataRoot
	// include host and port if running in vhosts mode
	host, port, _ := net.SplitHostPort(p.Host)
	if len(host) == 0 {
		host = p.Host
	}
	if len(port) > 0 {
		host += ":" + port
	}
	if req.Server.Config.Vhosts {
		res.Root = req.Server.Config.DataRoot + host + "/"
		res.Base = p.Scheme + "://" + host
	}

	// p.Path = p.String()[len(p.Scheme+"://"+p.Host):]
	if strings.HasPrefix(p.Path, "/") && len(p.Path) > 0 {
		p.Path = strings.TrimLeft(p.Path, "/")
	}

	if len(p.Path) == 0 {
		res.URI = p.String() + "/"
	} else {
		res.URI = p.String()
	}
	res.Obj = p
	res.File = p.Path
	res.Path = p.Path

	if req.Server.Config.Vhosts {
		res.File = res.Root + p.Path
	} else if len(req.Server.Config.DataRoot) > 0 {
		res.File = req.Server.Config.DataRoot + p.Path
	}

	res.Exists = true
	res.IsDir = false
	// check if file exits first
	if stat, err := os.Stat(res.File); os.IsNotExist(err) {
		res.Exists = false
	} else {
		res.ModTime = stat.ModTime()
		res.Size = stat.Size()
		// Add missing trailing slashes for dirs
		if stat.IsDir() {
			res.IsDir = true
			if !strings.HasSuffix(res.Path, "/") && len(res.Path) > 1 {
				res.Path += "/"
				res.File += "/"
				res.URI += "/"
			}
		} else {
			res.FileType, res.Extension, res.MaybeRDF = MimeLookup(res.File)
			if len(res.FileType) == 0 {
				res.FileType, err = GuessMimeType(res.File)
				if err != nil {
					req.Server.debug.Println(err)
				}
			}
		}
	}

	if len(res.Extension) == 0 {
		res.Extension = _path.Ext(res.File)
	}

	if strings.HasSuffix(res.Path, "/") {
		if filepath.Dir(filepath.Dir(res.Path)) == "." {
			res.ParentURI = res.Base + "/"
		} else {
			res.ParentURI = res.Base + "/" + filepath.Dir(filepath.Dir(res.Path)) + "/"
		}
	} else {
		res.ParentURI = res.Base + "/" + filepath.Dir(res.Path) + "/"
	}

	if strings.HasSuffix(res.Path, req.Server.Config.ACLSuffix) {
		res.AclURI = res.URI
		res.AclFile = res.File
		res.MetaURI = res.URI
		res.MetaFile = res.File
	} else if strings.HasSuffix(res.Path, req.Server.Config.MetaSuffix) {
		res.AclURI = res.URI + req.Server.Config.ACLSuffix
		res.AclFile = res.File + req.Server.Config.ACLSuffix
		res.MetaURI = res.URI
		res.MetaFile = res.File
	} else {
		res.AclURI = res.URI + req.Server.Config.ACLSuffix
		res.AclFile = res.File + req.Server.Config.ACLSuffix
		res.MetaURI = res.URI + req.Server.Config.MetaSuffix
		res.MetaFile = res.File + req.Server.Config.MetaSuffix
	}

	return res, nil
}
