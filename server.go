package gold

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	_path "path"
	"path/filepath"
	"strings"

	"github.com/presbrey/magicmime"
)

const (
	HCType     = "Content-Type"
	METASuffix = ",meta"
	ACLSuffix  = ",acl"
)

var (
	Debug     = false
	DirIndex  = []string{"index.html", "index.htm"}
	Skin      = "tabulator"
	Streaming = false // experimental

	methodsAll = []string{
		"GET", "PUT", "POST", "OPTIONS", "HEAD", "MKCOL", "DELETE", "PATCH",
	}

	magic *magicmime.Magic
)

func init() {
	var err error

	magic, err = magicmime.New()
	if err != nil {
		panic(err)
	}
}

type ldpath struct {
	Uri      string
	Base     string
	Path     string
	File     string
	AclUri   string
	AclFile  string
	MetaUri  string
	MetaFile string
}

func PathInfo(path string) (ldpath, error) {
	var res ldpath
	if len(path) == 0 {
		return res, errors.New("missing resource path")
	}

	p, err := url.Parse(path)
	if err != nil {
		return res, err
	}

	if len(p.Path) == 0 {
		path += "/"
	}

	if strings.HasPrefix(p.Path, "/") {
		p.Path = strings.TrimLeft(p.Path, "/")
	}

	res.Uri = path
	res.Base = p.Scheme + "://" + p.Host
	res.Path = p.Path
	res.File = p.Path

	if strings.HasSuffix(p.Path, ",acl") {
		res.AclUri = path
		res.AclFile = p.Path
		res.MetaUri = path
		res.MetaFile = p.Path
	} else if strings.HasSuffix(p.Path, ",meta") {
		res.AclUri = path + ACLSuffix
		res.AclFile = p.Path + ACLSuffix
		res.MetaUri = path
		res.MetaFile = p.Path
	} else {
		res.AclUri = path + ACLSuffix
		res.AclFile = p.Path + ACLSuffix
		res.MetaUri = path + METASuffix
		res.MetaFile = p.Path + METASuffix
	}

	return res, nil
}

type httpRequest struct{ *http.Request }

func (req httpRequest) BaseURI() string {
	scheme := "http"
	if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
		scheme += "s"
	}
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}
	if len(host) == 0 {
		host = "localhost"
	}
	if len(port) > 0 {
		port = ":" + port
	}
	if (scheme == "https" && port == ":443") || (scheme == "http" && port == ":80") {
		port = ""
	}
	return scheme + "://" + host + port + req.URL.Path
}

func (req httpRequest) Auth() string {
	user, _ := WebIDTLSAuth(req.TLS)
	if len(user) == 0 {
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		remoteAddr := net.ParseIP(host)
		user = "dns:" + remoteAddr.String()
	}
	return user
}

func (req httpRequest) ifMatch(etag string) bool {
	if len(etag) == 0 {
		return true
	}
	v := req.Header.Get("If-Match")
	if len(v) == 0 {
		return true
	}
	return v == "*" || v == etag
}

func (req httpRequest) ifNoneMatch(etag string) bool {
	if len(etag) == 0 {
		return true
	}
	v := req.Header.Get("If-None-Match")
	if len(v) == 0 {
		return true
	}
	return v != "*" && v != etag
}

type Server struct {
	http.Handler

	root   string
	vhosts bool
}

func NewServer(root string, vhosts bool) (s *Server) {
	s = new(Server)
	s.root = root
	s.vhosts = vhosts
	return
}

func (s *Server) reqPath(r *httpRequest) (path string) {
	return s.uriPath(r.BaseURI())
}

func (s *Server) uriPath(uri string) (path string) {
	lst := strings.SplitN(uri, "://", 2)
	if s.vhosts {
		paths := strings.SplitN(lst[1], "/", 2)
		host, _, _ := net.SplitHostPort(paths[0])
		if len(host) == 0 {
			host = paths[0]
		}
		path = strings.Join([]string{host, paths[1]}, "/")
	} else {
		path = strings.SplitN(lst[1], "/", 2)[1]
	}
	r := strings.Join([]string{s.root, path}, "/")
	if strings.HasPrefix(r, "./") {
		r = r[2:]
	}
	return r
}

type response struct {
	status  int
	headers http.Header

	argv []interface{}
}

func (r *response) respond(status int, a ...interface{}) *response {
	r.status = status
	r.argv = a
	return r
}

func (h *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		req.Body.Close()
	}()
	r := h.handle(w, &httpRequest{req})
	for key, _ := range r.headers {
		w.Header().Set(key, r.headers.Get(key))
	}
	if r.status > 0 {
		w.WriteHeader(r.status)
	}
	if len(r.argv) > 0 {
		fmt.Fprint(w, r.argv...)
	}
}

func (h *Server) handle(w http.ResponseWriter, req *httpRequest) (r *response) {
	r = new(response)
	var err error

	user := req.Auth()
	w.Header().Set("User", user)
	acl := NewWAC(req, h, user)

	dataMime := req.Header.Get(HCType)
	dataMime = strings.Split(dataMime, ";")[0]
	dataHasParser := len(mimeParser[dataMime]) > 0
	if len(dataMime) > 0 && !dataHasParser && req.Method != "PUT" {
		return r.respond(415, "Unsupported Media Type:", dataMime)
	}

	// Content Negotiation
	contentType := "text/turtle"
	acceptList, _ := req.Accept()
	if len(acceptList) > 0 && acceptList[0].SubType != "*" {
		contentType, err = acceptList.Negotiate(serializerMimes...)
		if err != nil {
			return r.respond(406, err) // Not Acceptable
		}
	}

	// CORS
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "60")
	w.Header().Set("MS-Author-Via", "DAV, SPARQL")

	// TODO: WAC
	origin := ""
	origins := req.Header["Origin"] // all CORS requests
	if len(origins) > 0 {
		origin = origins[0]
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	resource, _ := PathInfo(req.BaseURI())
	base := resource.Base

	// set ACL Link header
	w.Header().Set("Link", brack(resource.AclUri)+"; rel=acl")

	switch req.Method {
	case "OPTIONS":
		w.Header().Set("Accept-Patch", "application/json")
		w.Header().Set("Accept-Post", "text/turtle,application/json")

		// TODO: WAC
		corsReqH := req.Header["Access-Control-Request-Headers"] // CORS preflight only
		if len(corsReqH) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(corsReqH, ", "))
		}
		corsReqM := req.Header["Access-Control-Request-Method"] // CORS preflight only
		if len(corsReqM) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(corsReqM, ", "))
		} else {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(methodsAll, ", "))
		}
		if len(origin) < 1 {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Allow", strings.Join(methodsAll, ", "))
		return r.respond(200)

	case "GET", "HEAD":
		path := h.reqPath(req)

		var (
			magicType string
			maybeRDF  bool
			glob      bool
			globPath  string
			etag      string
		)

		// check for glob
		glob = false
		if strings.LastIndex(path, "/*") == len(path)-2 {
			glob = true
			globPath = path
			path = strings.TrimRight(path, "*")
			// TODO: use Depth header (WebDAV)
		}

		status := 501
		if !acl.AllowRead(req.BaseURI()) {
			return r.respond(403)
		}

		unlock := lock(path)
		defer unlock()
		g := NewGraph(req.BaseURI())

		if glob {
			matches, err := filepath.Glob(globPath)
			if err == nil {
				for _, file := range matches {
					stat, serr := os.Stat(file)
					if !stat.IsDir() && serr == nil {
						// TODO: check acls
						g.AppendFile(file, filepath.Base(file))
					}
				}
				status = 200
			}
		} else {
			stat, serr := os.Stat(path)
			if serr != nil {
				r.respond(500, serr)
			}
			switch {
			case os.IsNotExist(serr):
				status = 404
			case stat.IsDir():
				if !strings.HasSuffix(path, "/") {
					path = path + "/"
				}
				if len(DirIndex) > 0 && contentType == "text/html" {
					magicType = "text/html"
					maybeRDF = false
					for _, dirIndex := range DirIndex {
						_, xerr := os.Stat(path + dirIndex)
						status = 200
						if xerr == nil {
							path = _path.Join(path, dirIndex)
							break
						} else {
							//TODO load a skin to browse dir contents
							w.Header().Set(HCType, contentType)
							return r.respond(200, Skins[Skin])
						}
					}
				} else {
					if infos, err := ioutil.ReadDir(path); err == nil {
						magicType = "text/turtle"

						root := NewResource(req.BaseURI())
						g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#Directory"))
						g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer"))

						kb := NewGraph(resource.MetaUri)
						kb.ReadFile(resource.MetaFile)
						if kb.Len() > 0 {
							for triple := range kb.IterTriples() {
								var subject Term
								if kb.One(NewResource(path+METASuffix), nil, nil) != nil {
									subject = NewResource(req.BaseURI())
								} else {
									subject = triple.Subject
								}
								g.AddTriple(subject, triple.Predicate, triple.Object)
							}
						}

						showContainment := true
						showEmpty := false
						pref := ParsePreferHeader(req.Header.Get("Prefer"))
						if len(pref.headers) > 0 {
							w.Header().Set("Preference-Applied", "return=representation")
						}
						for _, include := range pref.Includes() {
							switch include {
							case "http://www.w3.org/ns/ldp#PreferContainment":
								showContainment = true
							case "http://www.w3.org/ns/ldp#PreferEmptyContainer":
								showEmpty = true
							}
						}
						for _, omit := range pref.Omits() {
							switch omit {
							case "http://www.w3.org/ns/ldp#PreferContainment":
								showContainment = false
							case "http://www.w3.org/ns/ldp#PreferEmptyContainer":
								showEmpty = false
							}
						}

						var s Term
						for _, info := range infos {
							if info != nil {
								f, err := PathInfo(resource.Uri + info.Name())
								if err != nil {
									r.respond(500, err)
								}
								if info.IsDir() {
									s = NewResource(f.Uri + "/")
									if !showEmpty {
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#Directory"))
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer"))
									}
								} else {
									s = NewResource(f.Uri)

									if !showEmpty {
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#File"))
										// add type if RDF resource
										//infoUrl, _ := url.Parse(info.Name())

										kb := NewGraph(f.Uri)
										kb.ReadFile(f.File)
										if kb.Len() > 0 {
											st := kb.One(NewResource(f.Uri), NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), nil)
											if st != nil && st.Object != nil {
												g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), st.Object)
											}
										}
									}
								}
								if !showEmpty {
									g.AddTriple(s, NewResource("http://www.w3.org/ns/posix/stat#mtime"), NewLiteral(fmt.Sprintf("%d", info.ModTime().Unix())))
									g.AddTriple(s, NewResource("http://www.w3.org/ns/posix/stat#size"), NewLiteral(fmt.Sprintf("%d", info.Size())))
								}
								if showContainment {
									g.AddTriple(root, NewResource("http://www.w3.org/ns/ldp#contains"), s)
								}
							}
						}
						status = 200
						maybeRDF = true
					}
				}
			default:
				if req.Method == "GET" && strings.Contains(contentType, "text/html") {
					w.Header().Set(HCType, contentType)
					return r.respond(200, Skins[Skin])
				} else {
					status = 200
					magicType, err = magic.TypeByFile(path)
					maybeRDF = magicType == "text/plain"
				}
			}
		}

		if status != 404 && len(path) > 0 {
			etag, err = NewETag(path)
			if err != nil {
				return r.respond(500, err)
			}
			w.Header().Set("ETag", etag)
		}

		if !req.ifMatch(etag) {
			return r.respond(412, "Precondition Failed")
		}
		if !req.ifNoneMatch(etag) {
			return r.respond(412, "Precondition Failed")
		}

		if status != 200 {
			return r.respond(status)
		}

		if maybeRDF {
			g.ReadFile(path)
			if g.Len() == 0 {
				maybeRDF = false
			} else {
				w.Header().Set(HCType, contentType)
				w.Header().Set("Triples", fmt.Sprintf("%d", g.Len()))
			}
		}

		if !maybeRDF && len(magicType) > 0 {
			if len(path) > 4 {
				if strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".htm") {
					magicType = "text/html"
				}
			}
			w.Header().Set(HCType, magicType)
			w.WriteHeader(status)
			if req.Method == "HEAD" {
				return
			}

			if status == 200 {
				f, err := os.Open(path)
				if err == nil {
					defer func() {
						if err := f.Close(); err != nil {
							log.Println(f.Name, err)
						}
					}()
					io.Copy(w, f)
				}
			}
			return
		}

		if req.Method == "HEAD" {
			return r.respond(status)
		}

		data := ""
		if Streaming {
			errCh := make(chan error, 8)
			go func() {
				rf, wf, err := os.Pipe()
				if err != nil {
					errCh <- err
					return
				}
				go func() {
					defer wf.Close()
					err := g.WriteFile(wf, contentType)
					if err != nil {
						errCh <- err
					}
				}()
				go func() {
					defer rf.Close()
					_, err := io.Copy(w, rf)
					if err != nil {
						errCh <- err
					} else {
						errCh <- nil
					}
				}()
			}()
			err = <-errCh
		} else {
			data, err = g.Serialize(contentType)
		}
		if err != nil {
			return r.respond(500, err)
		} else if len(data) > 0 {
			fmt.Fprint(w, data)
		}
		return

	case "PATCH", "POST", "PUT":
		path := h.reqPath(req)
		unlock := lock(path)
		defer unlock()

		// check append first
		if !acl.AllowAppend(req.BaseURI()) && !acl.AllowWrite(req.BaseURI()) {
			return r.respond(403)
		}

		etag, _ := NewETag(path)
		if !req.ifMatch(etag) {
			return r.respond(412, "Precondition Failed")
		}
		if !req.ifNoneMatch(etag) {
			return r.respond(412, "Precondition Failed")
		}

		g := NewGraph(req.BaseURI())

		// LDP
		gotLDP := false
		if req.Method == "POST" && len(req.Header.Get("Link")) > 0 {
			link := ParseLinkHeader(req.Header.Get("Link")).MatchRel("type")
			if link == "http://www.w3.org/ns/ldp#Resource" || link == "http://www.w3.org/ns/ldp#BasicContainer" {
				slug := req.Header.Get("Slug")
				stat, err := os.Stat(path)

				uuid, err := newUUID()
				if err != nil {
					return r.respond(500, err)
				}
				uuid = uuid[:6]

				if len(slug) > 0 && stat.IsDir() {
					if strings.HasPrefix(slug, "/") {
						slug = strings.TrimLeft(slug, "/")
					}
					//TODO: add an autoincrement
					slug = slug + "-" + uuid
				} else {
					slug = uuid
				}
				if strings.HasSuffix(path, "/") {
					path = path + slug
				} else {
					path = path + "/" + slug
				}

				newRes, err := PathInfo(base + "/" + path)
				if err != nil {
					return r.respond(500, err)
				}

				if link == "http://www.w3.org/ns/ldp#Resource" {
					w.Header().Set("Location", newRes.Uri)
					w.Header().Set("Link", "<"+newRes.Uri+">; rel=meta")
				} else if link == "http://www.w3.org/ns/ldp#BasicContainer" {
					if !strings.HasSuffix(path, "/") {
						path = path + "/"
					}
					newRes, err = PathInfo(base + "/" + path)
					if err != nil {
						return r.respond(500, err)
					}

					w.Header().Set("Location", newRes.Uri)

					err = os.MkdirAll(path, 0755)
					if err != nil {
						return r.respond(500, err)
					}

					w.Header().Set("Link", "<"+newRes.MetaUri+">; rel=meta")

					//Replace the subject with the dir path instead of the meta file path
					if dataHasParser {
						mg := NewGraph(newRes.Uri)
						mg.Parse(req.Body, dataMime)
						for triple := range mg.IterTriples() {
							subject := NewResource(newRes.Uri)
							g.AddTriple(subject, triple.Predicate, triple.Object)
						}
						f, err := os.OpenFile(newRes.MetaFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
						if err != nil {
							return r.respond(500, err)
						}
						defer f.Close()

						if err = g.WriteFile(f, ""); err != nil {
							return r.respond(500, err)
						}
					}
					return r.respond(201)
				}
				gotLDP = true
			}
		}

		if req.Method != "PUT" {
			g.ReadFile(path)
		}

		switch dataMime {
		case "application/json":
			g.JSONPatch(req.Body)
		case "application/sparql-update":
			sparql := NewSPARQL(g.URI())
			sparql.Parse(req.Body)
			g.SPARQLUpdate(sparql)
		default:
			if dataHasParser {
				g.Parse(req.Body, dataMime)
			}
		}

		if dataHasParser {
			w.Header().Set("Triples", fmt.Sprintf("%d", g.Len()))
		}

		err := os.MkdirAll(_path.Dir(path), 0755)
		if err != nil {
			return r.respond(500, err)
		}

		f := new(os.File)

		if dataMime != "multipart/form-data" {
			f, err = os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return r.respond(500, err)
			}
			defer f.Close()
		}

		if dataHasParser {
			err = g.WriteFile(f, "")
		} else {
			if dataMime == "multipart/form-data" {
				if Debug {
					log.Println("Got multipart")
				}
				err := req.ParseMultipartForm(100000)
				if err != nil {
					log.Printf("Cannot parse multipart data: %+v\n", err)
				} else {
					m := req.MultipartForm
					for elt := range m.File {
						files := m.File[elt]
						for i, _ := range files {
							if Debug {
								log.Printf("Preparing to write file: %+v\n", path+files[i].Filename)
							}
							file, err := files[i].Open()
							defer file.Close()
							if err != nil {
								if Debug {
									log.Printf("Cannot get file handler: %+v\n", err)
								}
								return r.respond(500)
							}
							dst, err := os.Create(path + files[i].Filename)
							defer dst.Close()
							if err != nil {
								if Debug {
									log.Printf("Cannot create destination file: %+v\n", err)
								}
								return r.respond(500)
							}
							if _, err := io.Copy(dst, file); err != nil {
								if Debug {
									log.Printf("Cannot copy data to destination file: %+v\n", err)
								}
								return r.respond(500)
							}
							if Debug {
								log.Printf("Wrote file: %+v\n", path+files[i].Filename)
							}
						}
					}
				}
			} else if dataMime == "application/x-www-form-urlencoded" {
				err := req.ParseForm()
				if err != nil {
					log.Printf("Cannot parse form data: %+v\n", err)
				} else {
					// parse form and write file
				}
			} else {
				_, err = io.Copy(f, req.Body)
			}
		}

		if err != nil {
			return r.respond(500)
		} else if req.Method == "PUT" || gotLDP {
			return r.respond(201)
		}

	case "DELETE":
		path := h.reqPath(req)
		unlock := lock(path)
		defer unlock()

		if !acl.AllowWrite(req.BaseURI()) {
			return r.respond(403)
		}
		if len(path) == 0 {
			return r.respond(500, "cannot DELETE /")
		}
		err := os.Remove(path)
		if err != nil {
			if os.IsNotExist(err) {
				return r.respond(404)
			}
			return r.respond(500, err)
		} else {
			_, err := os.Stat(path)
			if err == nil {
				return r.respond(409)
			}
		}
		return

	case "MKCOL":
		path := h.reqPath(req)
		unlock := lock(path)
		defer unlock()

		if !acl.AllowWrite(req.BaseURI()) {
			return r.respond(403)
		}
		err := os.MkdirAll(path, 0755)
		if err != nil {
			switch err.(type) {
			case *os.PathError:
				return r.respond(409, err)
			default:
				return r.respond(500, err)
			}
		} else {
			_, err := os.Stat(path)
			if err != nil {
				return r.respond(409, err)
			}
		}
		return r.respond(201)

	default:
		return r.respond(405, "Method Not Allowed:", req.Method)

	}
	return
}
