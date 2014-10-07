package gold

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
	Debug          = false
	DirIndex       = []string{"index.html", "index.htm"}
	Skin           = "tabulator"
	FileManagerUri = "https://linkeddata.github.io/warp/#list/"
	Streaming      = false // experimental

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
	Obj      *url.URL
	Uri      string
	Base     string
	Path     string
	File     string
	FileType string
	AclUri   string
	AclFile  string
	MetaUri  string
	MetaFile string
}

func GetServerRoot() string {
	serverRoot, err := os.Getwd()
	if err != nil {
		DebugLog("Server", "Error starting server:"+err.Error())
		os.Exit(1)
	}

	if !strings.HasSuffix(serverRoot, "/") {
		serverRoot += "/"
	}
	return serverRoot
}

func DebugLog(location string, msg string) {
	if Debug {
		println("["+location+"]", msg)
	}
}

func (s *Server) pathInfo(path string) (ldpath, error) {
	var res ldpath
	if len(path) == 0 {
		return res, errors.New("missing resource path")
	}

	// hack - if source URI contains "one%2b+%2btwo" then it is
	// normally decoded to "one+ +two", but Go parses it to
	// "one+++two", so we replace the plus with a blank space
	// strings.Replace(path, "+", "%20", -1)

	p, err := url.Parse(path)
	if err != nil {
		return res, err
	}

	root := s.root
	if root == "." {
		root = ""
	}

	// Add missing trailing slashes for dirs
	res.FileType, err = magic.TypeByFile(root + p.Path)
	if err == nil {
		if res.FileType == "inode/directory" && !strings.HasSuffix(p.Path, "/") {
			p.Path += "/"
		}
	}

	if strings.HasPrefix(p.Path, "/") && len(p.Path) > 0 {
		p.Path = strings.TrimLeft(p.Path, "/")
	} else if len(p.Path) == 0 {
		p.Path += "/"
	}

	// hack: url.EncodeQuery() uses + instead of %20 to encode whitespaces in the path
	//p.Path = strings.Replace(p.Path, " ", "%20", -1)

	if len(p.Path) == 0 {
		res.Uri = p.String() + "/"
	} else {
		res.Uri = p.String()
	}
	res.Obj = p
	res.Base = p.Scheme + "://" + p.Host
	res.Path = p.Path
	res.File = p.Path

	if strings.HasSuffix(res.Path, ",acl") {
		res.AclUri = res.Uri
		res.AclFile = res.Path
		res.MetaUri = res.Uri
		res.MetaFile = res.Path
	} else if strings.HasSuffix(res.Path, ",meta") || strings.HasSuffix(res.Path, ",meta/") {
		res.AclUri = res.Uri + ACLSuffix
		res.AclFile = res.Path + ACLSuffix
		res.MetaUri = res.Uri
		res.MetaFile = res.Path
	} else {
		res.AclUri = res.Uri + ACLSuffix
		res.AclFile = res.Path + ACLSuffix
		res.MetaUri = res.Uri + METASuffix
		res.MetaFile = res.Path + METASuffix
	}

	if s.vhosts {
		host, _, _ := net.SplitHostPort(p.Host)
		if len(host) == 0 {
			host = p.Host
		}

		res.File = host + "/" + res.File
		res.AclFile = host + "/" + res.AclFile
		res.MetaFile = host + "/" + res.MetaFile
	}

	if len(root) > 0 {
		if !strings.HasSuffix(root, "/") {
			root = root + "/"
		}
		res.File = root + res.File
		res.AclFile = root + res.AclFile
		res.MetaFile = root + res.MetaFile
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

func (req *httpRequest) Auth() string {
	user, _ := WebIDTLSAuth(req.TLS)
	if len(user) == 0 {
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		remoteAddr := net.ParseIP(host)
		user = "dns:" + remoteAddr.String()
	}
	DebugLog("Server", "Request User: "+user)
	return user
}

func (req httpRequest) ifMatch(etag string) bool {
	if len(etag) == 0 {
		return true
	}
	if len(req.Header.Get("If-Match")) == 0 {
		return true
	}
	val := strings.Split(req.Header.Get("If-Match"), ",")
	for _, v := range val {
		v = strings.TrimSpace(v)
		if v == "*" || v == etag {
			return true
		}
	}
	return false
}

func (req httpRequest) ifNoneMatch(etag string) bool {
	if len(etag) == 0 {
		return true
	}
	if len(req.Header.Get("If-None-Match")) == 0 {
		return true
	}
	val := strings.Split(req.Header.Get("If-None-Match"), ",")
	for _, v := range val {
		v = strings.TrimSpace(v)
		if v != "*" && v != etag {
			return true
		}
	}
	return false
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
	DebugLog("Server", "---- Server started ----")
	DebugLog("Server", "Waiting for connections...")
	return
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

	DebugLog("Server", "------ New "+req.Method+" request from "+req.RemoteAddr+" ------")

	user := req.Auth()
	w.Header().Set("User", user)
	acl := NewWAC(req, h, user)

	dataMime := req.Header.Get(HCType)
	dataMime = strings.Split(dataMime, ";")[0]
	dataHasParser := len(mimeParser[dataMime]) > 0
	if len(dataMime) > 0 && dataMime != "multipart/form-data" && !dataHasParser && req.Method != "PUT" {
		return r.respond(415, "Unsupported Media Type:", dataMime)
	}

	DebugLog("Server", "Content-Type: "+dataMime)

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
	w.Header().Set("Access-Control-Expose-Headers", "User, Triples, Location, Link, Vary, Last-Modified, Content-Length")
	w.Header().Set("Access-Control-Max-Age", "60")
	w.Header().Set("MS-Author-Via", "DAV, SPARQL")

	// TODO: WAC
	origin := ""
	origins := req.Header["Origin"] // all CORS requests
	if len(origins) > 0 {
		origin = origins[0]
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	resource, _ := h.pathInfo(req.BaseURI())
	DebugLog("Server", "Resource URI: "+resource.Uri)
	DebugLog("Server", "Resource Path: "+resource.File)

	// set ACL Link header
	w.Header().Set("Link", brack(resource.AclUri)+"; rel=\"acl\", "+brack(resource.MetaUri)+"; rel=\"meta\"")

	// generic headers
	w.Header().Set("Accept-Patch", "application/json")
	w.Header().Set("Accept-Post", "text/turtle, application/json")
	w.Header().Set("Allow", strings.Join(methodsAll, ", "))

	switch req.Method {
	case "OPTIONS":
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

		// set LDP Link headers
		stat, err := os.Stat(resource.File)
		if err == nil && stat.IsDir() {
			w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")
		}
		w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

		return r.respond(200)

	case "GET", "HEAD":
		var (
			magicType string
			maybeRDF  bool
			glob      bool
			globPath  string
			etag      string
		)

		// check for glob
		glob = false
		if strings.Contains(filepath.Base(resource.Path), "*") {
			glob = true
			globPath = resource.Path
			path := filepath.Dir(resource.Path) + "/"
			if path == "./" {
				path = ""
			}
			resource, err = h.pathInfo(resource.Base + "/" + path)
			if err != nil {
				return r.respond(500, err)
			}
			// TODO: use Depth header (WebDAV)
		}

		// overwrite ACL Link header
		w.Header().Set("Link", brack(resource.AclUri)+"; rel=\"acl\", "+brack(resource.MetaUri)+"; rel=\"meta\"")

		// set LDP Link headers
		stat, err := os.Stat(resource.File)
		if err != nil {
			r.respond(500, err.Error())
		} else if stat.IsDir() {
			w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")
		}
		if req.Method == "HEAD" && stat != nil {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
		}
		w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

		status := 501
		if !acl.AllowRead(resource.Uri) {
			return r.respond(403, "403 - Forbidden")
		}

		unlock := lock(resource.File)
		defer unlock()

		if os.IsNotExist(err) {
			return r.respond(404, err)
		} else {
			etag, err = NewETag(resource.File)
			if err != nil {
				return r.respond(500, err)
			}
			w.Header().Set("ETag", "\""+etag+"\"")
		}

		if !req.ifMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}
		if !req.ifNoneMatch("\"" + etag + "\"") {
			return r.respond(304, "304 - Not Modified")
		}

		g := NewGraph(resource.Uri)

		switch {
		case stat.IsDir():
			if len(DirIndex) > 0 && contentType == "text/html" {
				magicType = "text/html"
				maybeRDF = false
				for _, dirIndex := range DirIndex {
					_, xerr := os.Stat(resource.File + dirIndex)
					status = 200
					if xerr == nil {
						resource, err = h.pathInfo(resource.Base + "/" + resource.Path + dirIndex)
						if err != nil {
							return r.respond(500, err)
						}
						w.Header().Set("Link", "<"+resource.MetaUri+">; rel=\"meta\", <"+resource.AclUri+">; rel=\"acl\"")
						break
					} else {
						//TODO load file manager skin from local preference file
						w.Header().Set(HCType, contentType)
						urlStr := FileManagerUri + resource.Obj.Scheme + "/" + resource.Obj.Host + "/" + resource.Obj.Path
						http.Redirect(w, req.Request, urlStr, 303)
					}
				}
			} else {
				magicType = "text/turtle"

				w.Header().Add("Link", "<"+resource.MetaUri+">; rel=\"meta\"")

				root := NewResource(resource.Uri)
				g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#Directory"))
				g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#Container"))
				g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer"))

				g.AddTriple(root, NewResource("http://www.w3.org/ns/posix/stat#mtime"), NewLiteral(fmt.Sprintf("%d", stat.ModTime().Unix())))
				g.AddTriple(root, NewResource("http://www.w3.org/ns/posix/stat#size"), NewLiteral(fmt.Sprintf("%d", stat.Size())))

				kb := NewGraph(resource.MetaUri)
				kb.ReadFile(resource.MetaFile)
				if kb.Len() > 0 {
					for triple := range kb.IterTriples() {
						var subject Term
						if kb.One(NewResource(resource.MetaUri), nil, nil) != nil {
							subject = NewResource(resource.Uri)
						} else {
							subject = triple.Subject
						}
						g.AddTriple(subject, triple.Predicate, triple.Object)
					}
				}

				if glob {
					matches, err := filepath.Glob(globPath)
					if err == nil {
						for _, file := range matches {
							stat, serr := os.Stat(file)
							if !stat.IsDir() && serr == nil {
								// TODO: check acls
								guessType, _ := magic.TypeByFile(file)
								if guessType == "text/plain" {
									if acl.AllowRead(resource.Base + "/" + file) {
										g.AppendFile(file, resource.Base+"/"+file)
										g.AddTriple(root, NewResource("http://www.w3.org/ns/ldp#contains"), NewResource(resource.Base+"/"+file))
									}
								}
							}
						}
					}
				} else {
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

					if infos, err := ioutil.ReadDir(resource.File); err == nil {
						var s Term
						for _, info := range infos {
							if info != nil {
								res := resource.Uri + info.Name()
								if info.IsDir() {
									res += "/"
								}
								f, err := h.pathInfo(res)
								if err != nil {
									r.respond(500, err)
								}
								if info.IsDir() {
									s = NewResource(f.Uri)
									if !showEmpty {
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#Directory"))
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer"))
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#Container"))
									}
									kb := NewGraph(f.Uri)
									kb.ReadFile(f.MetaFile)
									if kb.Len() > 0 {
										for _, st := range kb.All(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), nil) {
											if st != nil && st.Object != nil {
												g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), st.Object)
											}
										}
									}
								} else {
									s = NewResource(f.Uri)
									if !showEmpty {
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#File"))
										// add type if RDF resource
										//infoUrl, _ := url.Parse(info.Name())
										guessType, _ := magic.TypeByFile(f.File)

										if guessType == "text/plain" {
											// open file and attempt to read the first line
											// Open an input file, exit on error.
											fd, err := os.Open(f.File)
											if err != nil {
												DebugLog("Server", "GET find mime type error:"+err.Error())
											}
											defer fd.Close()

											scanner := bufio.NewScanner(fd)

											// stop after the first line
											for scanner.Scan() {
												if strings.HasPrefix(scanner.Text(), "@prefix") {
													kb := NewGraph(f.Uri)
													kb.ReadFile(f.File)
													if kb.Len() > 0 {
														for _, st := range kb.All(NewResource(f.Uri), NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), nil) {
															if st != nil && st.Object != nil {
																g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), st.Object)
															}
														}
													}
												}
												break
											}
											// log potential errors
											if err := scanner.Err(); err != nil {
												DebugLog("Server", "GET scan err: "+scanner.Err().Error())
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
					}
				}
				status = 200
				maybeRDF = true
			}
		default:
			if req.Method == "GET" && strings.Contains(contentType, "text/html") {
				w.Header().Del("ETag")
				magicType, err = magic.TypeByFile(resource.File)
				maybeRDF = magicType == "text/plain"
				w.Header().Set("Link", "<"+resource.MetaUri+">; rel=meta, <"+resource.AclUri+">; rel=acl")
				if maybeRDF {
					w.Header().Set(HCType, contentType)
					return r.respond(200, Skins[Skin])
				} else {
					w.Header().Set(HCType, magicType)
					w.WriteHeader(200)
					f, err := os.Open(resource.File)
					if err == nil {
						defer func() {
							if err := f.Close(); err != nil {
								DebugLog("Server", "GET os.Open err: "+err.Error())
							}
						}()
						io.Copy(w, f)
					}
					return
				}
			} else {
				status = 200
				magicType, err = magic.TypeByFile(resource.File)
				maybeRDF = magicType == "text/plain"
			}
		}

		if status != 200 {
			return r.respond(status)
		}

		if maybeRDF {
			g.ReadFile(resource.File)
			if g.Len() == 0 {
				maybeRDF = false
			} else {
				w.Header().Set(HCType, contentType)
				w.Header().Set("Triples", fmt.Sprintf("%d", g.Len()))
			}
		}

		if req.Method == "HEAD" {
			return r.respond(status)
		}

		if !maybeRDF && len(magicType) > 0 {
			if len(resource.Path) > 4 {
				if strings.HasSuffix(resource.Path, ".html") || strings.HasSuffix(resource.Path, ".htm") {
					magicType = "text/html"
				}
			}
			w.Header().Set(HCType, magicType)
			w.WriteHeader(status)

			if status == 200 {
				f, err := os.Open(resource.File)
				if err == nil {
					defer func() {
						if err := f.Close(); err != nil {
							DebugLog("Server", "GET f.Close err:"+err.Error())
						}
					}()
					io.Copy(w, f)
				}
			}
			return
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

	case "PATCH":
		unlock := lock(resource.File)
		defer unlock()

		// check append first
		if !acl.AllowAppend(resource.Uri) && !acl.AllowWrite(resource.Uri) {
			return r.respond(403, "403 - Forbidden")
		}

		etag, _ := NewETag(resource.File)
		if !req.ifMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}
		if !req.ifNoneMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}

		if dataHasParser {
			g := NewGraph(resource.Uri)
			g.ReadFile(resource.File)

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

			f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				DebugLog("Server", "PATCH os.OpenFile err: "+err.Error())
				return r.respond(500, err)
			}
			defer f.Close()

			err = g.WriteFile(f, "text/turtle")
			if err != nil {
				DebugLog("Server", "PATCH g.WriteFile err: "+err.Error())
			}
			w.Header().Set("Triples", fmt.Sprintf("%d", g.Len()))

			if err != nil {
				return r.respond(500, err)
			}
		}

	case "POST":
		unlock := lock(resource.File)
		defer unlock()

		// check append first
		if !acl.AllowAppend(resource.Uri) && !acl.AllowWrite(resource.Uri) {
			return r.respond(403, "403 - Forbidden")
		}

		etag, _ := NewETag(resource.File)
		if !req.ifMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}
		if !req.ifNoneMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}

		// LDP
		isNew := false
		stat, err := os.Stat(resource.File)
		if err == nil && stat.IsDir() && dataMime != "multipart/form-data" {
			link := ParseLinkHeader(req.Header.Get("Link")).MatchRel("type")
			slug := req.Header.Get("Slug")

			uuid, err := newUUID()
			if err != nil {
				DebugLog("Server", "POST LDP UUID err: "+err.Error())
				return r.respond(500, err)
			}
			uuid = uuid[:6]

			if !strings.HasSuffix(resource.Path, "/") {
				resource.Path += "/"
			}

			if len(slug) > 0 {
				if strings.HasPrefix(slug, "/") {
					slug = strings.TrimLeft(slug, "/")
				}
				if strings.HasSuffix(slug, "/") {
					slug = strings.TrimRight(slug, "/")
				}
				// TODO check if resource exists already and respond with 409
				s, _ := os.Stat(resource.File + slug)
				if s != nil {
					DebugLog("Server", "POST LDP - A resource with the same name already exists: "+resource.Path+slug)
					return r.respond(409, "409 - Conflict! A resource with the same name already exists.")
				}
			} else {
				slug = uuid
			}
			resource.Path += slug

			if len(link) > 0 && link == "http://www.w3.org/ns/ldp#BasicContainer" {
				if !strings.HasSuffix(resource.Path, "/") {
					resource.Path += "/"
				}
				resource, err = h.pathInfo(resource.Base + "/" + resource.Path)
				if err != nil {
					DebugLog("Server", "POST LDPC h.pathInfo err: "+err.Error())
					return r.respond(500, err)
				}

				w.Header().Set("Location", resource.Uri)
				w.Header().Set("Link", brack(resource.MetaUri)+"; rel=\"meta\", "+brack(resource.AclUri)+"; rel=\"acl\"")
				w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
				w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")

				err = os.MkdirAll(resource.File, 0755)
				if err != nil {
					DebugLog("Server", "POST LDPC os.MkdirAll err: "+err.Error())
					return r.respond(500, err)
				}
				DebugLog("Server", "Created dir "+resource.File)

				//Replace the subject with the dir path instead of the meta file path
				if dataHasParser {
					g := NewGraph(resource.Uri)
					mg := NewGraph(resource.Uri)
					mg.Parse(req.Body, dataMime)
					for triple := range mg.IterTriples() {
						subject := NewResource(".")
						g.AddTriple(subject, triple.Predicate, triple.Object)
					}

					f, err := os.OpenFile(resource.MetaFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
					if err != nil {
						DebugLog("Server", "POST LDPC os.OpenFile err: "+err.Error())
						return r.respond(500, err)
					}
					defer f.Close()

					if err = g.WriteFile(f, ""); err != nil {
						DebugLog("Server", "POST LDPC g.WriteFile err: "+err.Error())
						return r.respond(500, err)
					}
				}
				w.Header().Set("Location", resource.Uri)
				return r.respond(201)
			} else {
				resource, err = h.pathInfo(resource.Base + "/" + resource.Path)
				if err != nil {
					DebugLog("Server", "POST LDPR h.pathInfo err: "+err.Error())
					return r.respond(500, err)
				}
				w.Header().Set("Location", resource.Uri)
				w.Header().Set("Link", "<"+resource.MetaUri+">; rel=\"meta\", <"+resource.AclUri+">; rel=\"acl\"")
				// LDP header
				w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
			}
			isNew = true
		}

		if stat == nil {
			err = os.MkdirAll(_path.Dir(resource.File), 0755)
			if err != nil {
				DebugLog("Server", "POST MkdirAll err: "+err.Error())
				return r.respond(500, err)
			} else {
				DebugLog("Server", "Created resource "+_path.Dir(resource.File))
			}
		}

		if dataMime == "multipart/form-data" {
			err := req.ParseMultipartForm(100000)
			if err != nil {
				DebugLog("Server", "POST parse multipart data err: "+err.Error())
			} else {
				m := req.MultipartForm
				for elt := range m.File {
					files := m.File[elt]
					for i, _ := range files {
						file, err := files[i].Open()
						defer file.Close()
						if err != nil {
							DebugLog("Server", "POST multipart/form f.Open err: "+err.Error())
							return r.respond(500, err)
						}
						newFile := ""
						if filepath.Base(resource.Path) == files[i].Filename {
							newFile = resource.File
						} else {
							newFile = resource.File + files[i].Filename
						}
						dst, err := os.Create(newFile)
						defer dst.Close()
						if err != nil {
							DebugLog("Server", "POST multipart/form os.Create err: "+err.Error())
							return r.respond(500, err)
						}
						if _, err := io.Copy(dst, file); err != nil {
							DebugLog("Server", "POST multipart/form io.Copy err: "+err.Error())
							return r.respond(500, err)
						}
					}
				}
				return r.respond(201)
			}
		} else {
			stat, err = os.Stat(resource.File)
			if os.IsNotExist(err) {
				isNew = true
			} else if os.IsExist(err) && stat.IsDir() {
				resource.File = resource.File + "/" + METASuffix
			}

			if dataHasParser {
				g := NewGraph(resource.Uri)
				g.ReadFile(resource.File)

				switch dataMime {
				case "application/json":
					g.JSONPatch(req.Body)
				case "application/sparql-update":
					sparql := NewSPARQL(g.URI())
					sparql.Parse(req.Body)
					g.SPARQLUpdate(sparql)
				default:
					g.Parse(req.Body, dataMime)
				}
				f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					DebugLog("Server", "POST os.OpenFile err: "+err.Error())
					return r.respond(500, err.Error())
				}
				defer f.Close()

				err = g.WriteFile(f, "text/turtle")
				if err != nil {
					DebugLog("Server", "POST g.WriteFile err: "+err.Error())
				} else {
					DebugLog("Server", "Wrote resource file: "+resource.File)
				}
				w.Header().Set("Triples", fmt.Sprintf("%d", g.Len()))
			} else {
				f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					DebugLog("Server", "POST os.OpenFile err: "+err.Error())
					return r.respond(500, err.Error())
				}
				defer f.Close()
				_, err = io.Copy(f, req.Body)
				if err != nil {
					DebugLog("Server", "POST os.OpenFile err: "+err.Error())
					return r.respond(500, err.Error())
				}
			}

			if isNew {
				return r.respond(201)
			} else {
				return r.respond(200)
			}
		}

	case "PUT":
		unlock := lock(resource.File)
		defer unlock()

		// LDP header
		w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

		// check append first
		if !acl.AllowAppend(resource.Uri) && !acl.AllowWrite(resource.Uri) {
			return r.respond(403, "403 - Forbidden")
		}

		etag, _ := NewETag(resource.File)
		if !req.ifMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}
		if !req.ifNoneMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}

		// LDP PUT should be merged with LDP POST into a common LDP "method" switch
		link := ParseLinkHeader(req.Header.Get("Link")).MatchRel("type")
		if len(link) > 0 && link == "http://www.w3.org/ns/ldp#BasicContainer" {
			err := os.MkdirAll(resource.File, 0755)
			if err != nil {
				DebugLog("Server", "PUT MkdirAll err: "+err.Error())
				return r.respond(500, err)
			}
			// refresh resource and set the right headers
			resource, err = h.pathInfo(resource.Uri)
			w.Header().Set("Link", "<"+resource.MetaUri+">; rel=\"meta\", <"+resource.AclUri+">; rel=\"acl\"")
			// LDP header
			w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

			return r.respond(201)
		} else {
			err := os.MkdirAll(_path.Dir(resource.File), 0755)
			if err != nil {
				DebugLog("Server", "PUT MkdirAll err: "+err.Error())
				return r.respond(500, err)
			}
		}

		isNew := true
		stat, err := os.Stat(resource.File)
		if os.IsExist(err) {
			isNew = false
		}

		f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			DebugLog("Server", "PUT os.OpenFile err: "+err.Error())
			if stat.IsDir() {
				w.Header().Add("Link", brack(resource.Uri)+"; rel=\"describedby\"")
				return r.respond(406, "406 - Cannot use PUT on a directory.")
			} else {
				return r.respond(500, err)
			}
		}
		defer f.Close()

		if dataHasParser {
			g := NewGraph(resource.Uri)
			g.Parse(req.Body, dataMime)
			err = g.WriteFile(f, "text/turtle")
			if err != nil {
				DebugLog("Server", "PUT g.WriteFile err: "+err.Error())
			}
			w.Header().Set("Triples", fmt.Sprintf("%d", g.Len()))
		} else {
			_, err = io.Copy(f, req.Body)
			if err != nil {
				DebugLog("Server", "PUT io.Copy err: "+err.Error())
			}
		}

		if err != nil {
			return r.respond(500, err)
		} else if isNew {
			return r.respond(201)
		} else {
			return r.respond(200)
		}

	case "DELETE":
		unlock := lock(resource.Path)
		defer unlock()

		if !acl.AllowWrite(resource.Uri) {
			return r.respond(403, "403 - Forbidden")
		}
		if len(resource.Path) == 0 {
			return r.respond(500, "500 - Cannot DELETE /")
		}
		err := os.Remove(resource.File)
		if err != nil {
			if os.IsNotExist(err) {
				return r.respond(404, "404 - Not found")
			}
			return r.respond(500, err)
		} else {
			_, err := os.Stat(resource.File)
			if err == nil {
				return r.respond(409, err)
			}
		}
		return

	case "MKCOL":
		unlock := lock(resource.File)
		defer unlock()

		if !acl.AllowWrite(resource.Uri) {
			return r.respond(403, "403 - Forbidden")
		}
		err := os.MkdirAll(resource.File, 0755)
		if err != nil {
			switch err.(type) {
			case *os.PathError:
				return r.respond(409, err)
			default:
				return r.respond(500, err)
			}
		} else {
			_, err := os.Stat(resource.File)
			if err != nil {
				return r.respond(409, err)
			}
		}
		return r.respond(201)

	default:
		return r.respond(405, "405 - Method Not Allowed:", req.Method)
	}
	return
}
