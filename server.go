package gold

import (
	"bufio"
	"bytes"
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

	"github.com/boltdb/bolt"
	"github.com/gorilla/securecookie"
	"golang.org/x/net/webdav"

	"github.com/linkeddata/gold/pkg/apps"
//	"github.com/linkeddata/gold/pkg/routes"
)

const (
	// HCType is the header Content-Type
	HCType = "Content-Type"
	// SystemPrefix is the generic name for the system-reserved namespace (e.g. APIs)
	SystemPrefix = ",account"
	// LoginEndpoint is the link to the login page
	LoginEndpoint = SystemPrefix + "/login"
	// ProxyPath provides CORS proxy (empty to disable)
	ProxyPath = ",proxy"
	// QueryPath provides link-following support for twinql
	QueryPath = ",query"
	// AgentPath is the path to the agent's WebID profile
	AgentPath = ",agent"
	// RDFExtension is the default extension for RDF documents (i.e. turtle for now)
	RDFExtension = ".ttl"
)

var (
	// Streaming (stream data or not)
	Streaming = false // experimental

	debugFlags  = log.Flags() | log.Lshortfile
	debugPrefix = "[debug] "

	methodsAll = []string{
		"OPTIONS", "HEAD", "GET",
		"PATCH", "POST", "PUT", "MKCOL", "DELETE",
		"COPY", "MOVE", "LOCK", "UNLOCK",
	}
)

type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

// Server object contains http handler, root where the data is found and whether it uses vhosts or not
type Server struct {
	http.Handler

	Config     *ServerConfig
	cookie     *securecookie.SecureCookie
	cookieSalt []byte
	debug      *log.Logger
	webdav     *webdav.Handler
	BoltDB     *bolt.DB
}

type httpRequest struct {
	*http.Request
	*Server
	AcceptType  string
	ContentType string
	User        string
	IsOwner     bool
}

func (req httpRequest) BaseURI() string {
	scheme := "http"
	if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
		scheme += "s"
	}
	reqHost := req.Host
	if len(req.Header.Get("X-Forward-Host")) > 0 {
		reqHost = req.Header.Get("X-Forward-Host")
	}
	host, port, err := net.SplitHostPort(reqHost)
	if err != nil {
		host = reqHost
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

func handleStatusText(status int, err error) string {
	switch status {
	case 200:
		return "HTTP 200 - OK"
	case 401:
		return Apps["401"]
	case 403:
		return Apps["403"]
	case 404:
		return "HTTP 404 - Not found\n\n" + err.Error()
	case 500:
		return "HTTP 500 - Internal Server Error\n\n" + err.Error()
	default: // 501
		return "HTTP 501 - Not implemented\n\n" + err.Error()
	}
}

// NewServer is used to create a new Server instance
func NewServer(config *ServerConfig) *Server {
	s := &Server{
		Config:     config,
		cookie:     securecookie.New(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32)),
		cookieSalt: securecookie.GenerateRandomKey(8),
		webdav: &webdav.Handler{
			FileSystem: webdav.Dir(config.DataRoot),
			LockSystem: webdav.NewMemLS(),
		},
	}
	AddRDFExtension(s.Config.ACLSuffix)
	AddRDFExtension(s.Config.MetaSuffix)
	if config.Debug {
		s.debug = log.New(os.Stderr, debugPrefix, debugFlags)
	} else {
		s.debug = log.New(ioutil.Discard, "", 0)
	}
	s.debug.Println("---- starting server ----")
	s.debug.Printf("config: %#v\n", s.Config)
	return s
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

func (r *response) respondNotFound() *response {
	page404, err := apps.NotFound()
	if err != nil {
		return r.respond(500, err)
	}
	return r.respond(404, page404)
}

// ServeHTTP handles the response
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// add HSTS
	if s.Config.HSTS {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}

	origin := ""
	origins := req.Header["Origin"] // all CORS requests
	if len(origins) > 0 {
		origin = origins[0]
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	if len(origin) < 1 {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}

	if websocketUpgrade(req) {
		websocketServe(w, req)
		return
	}

	defer func() {
		req.Body.Close()
	}()
	r := s.handle(w, &httpRequest{req, s, "", "", "", false})
	for key := range r.headers {
		w.Header().Set(key, r.headers.Get(key))
	}
	if r.status > 0 {
		w.WriteHeader(r.status)
	}
	if len(r.argv) > 0 {
		fmt.Fprint(w, r.argv...)
	}
}

// Twinql Query
func TwinqlQuery(w http.ResponseWriter, req *httpRequest, s *Server) *response {
	r := new(response)

	err := ProxyReq(w, req, s, s.Config.QueryTemplate)
	if err != nil {
		s.debug.Println("Query error:", err.Error())
	}
	return r
}

// Proxy requests
func ProxyReq(w http.ResponseWriter, req *httpRequest, s *Server, reqUrl string) error {
	uri, err := url.Parse(reqUrl)
	if err != nil {
		return err
	}
	host := uri.Host
	if !s.Config.ProxyLocal {
		if strings.HasPrefix(host, "10.") ||
			strings.HasPrefix(host, "172.16.") ||
			strings.HasPrefix(host, "192.168.") ||
			strings.HasPrefix(host, "localhost") {
			return errors.New("Proxying requests to the local network is not allowed.")
		}
	}
	if len(req.FormValue("key")) > 0 {
		token, err := decodeQuery(req.FormValue("key"))
		if err != nil {
			s.debug.Println(err.Error())
		}
		user, err := GetAuthzFromToken(token, req)
		if err != nil {
			s.debug.Println(err.Error())
		} else {
			s.debug.Println("Authorization valid for user", user)
		}
		req.User = user
	}

	if len(req.Header.Get("Authorization")) > 0 {
		token, err := ParseBearerAuthorizationHeader(req.Header.Get("Authorization"))
		if err != nil {
			s.debug.Println(err.Error())
		}
		user, err := GetAuthzFromToken(token, req)
		if err != nil {
			s.debug.Println(err.Error())
		} else {
			s.debug.Println("Authorization valid for user", user)
		}
		req.User = user
	}

	req.URL = uri
	req.Host = host
	req.RequestURI = uri.RequestURI()
	req.Header.Set("User", req.User)
	proxy.ServeHTTP(w, req.Request)
	return nil
}

func (s *Server) handle(w http.ResponseWriter, req *httpRequest) (r *response) {
	r = new(response)
	var err error

	defer func() {
		if rec := recover(); rec != nil {
			s.debug.Println("\nRecovered from panic: ", rec)
		}
	}()

	s.debug.Println("\n------ New " + req.Method + " request from " + req.RemoteAddr + " ------")

	// CORS
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "User, Location, Link, Vary, Last-Modified, WWW-Authenticate, Content-Length, Content-Type, Accept-Patch, Accept-Post, Allow, Updates-Via, Ms-Author-Via")
	w.Header().Set("Access-Control-Max-Age", "1728000")

	// RWW
	w.Header().Set("MS-Author-Via", "DAV, SPARQL")
	w.Header().Set("Updates-Via", "wss://"+req.Host+"/")

 	// Get request key
	rKey := req.Request.FormValue("key")

	// Authentication
	user := req.authn(w)
	req.User = user
	w.Header().Set("User", user)
	acl := NewWAC(req, s, w, user, rKey)

	// check if is owner
	req.IsOwner = false
	resource, _ := req.pathInfo(req.BaseURI())
	if len(user) > 0 {
		aclStatus, err := acl.AllowWrite(resource.Base)
		if aclStatus == 200 && err == nil {
			req.IsOwner = true
		}
	}

	// Intercept API requests
	if strings.Contains(req.Request.URL.Path, "/"+SystemPrefix) && req.Method != "OPTIONS" {
		resp := HandleSystem(w, req, s)
		if resp.Bytes != nil && len(resp.Bytes) > 0 {
			// copy raw bytes
			io.Copy(w, bytes.NewReader(resp.Bytes))
			return
		}
		return r.respond(resp.Status, resp.Body)
	}

	// Proxy requests
	if ProxyPath != "" && strings.HasSuffix(req.URL.Path, ProxyPath) {
		err = ProxyReq(w, req, s, s.Config.ProxyTemplate+req.FormValue("uri"))
		if err != nil {
			s.debug.Println("Proxy error:", err.Error())
		}
		return
	}

	// Query requests
	if req.Method == "POST" && QueryPath != "" &&
		strings.Contains(req.URL.Path, QueryPath) &&
		len(s.Config.QueryTemplate) > 0 {
		return TwinqlQuery(w, req, s)
	}

	s.debug.Println(req.RemoteAddr + " requested resource URI: " + req.URL.String())
	s.debug.Println(req.RemoteAddr + " requested resource Path: " + resource.File)

	dataMime := req.Header.Get(HCType)
	dataMime = strings.Split(dataMime, ";")[0]
	dataHasParser := len(mimeParser[dataMime]) > 0
	if len(dataMime) > 0 {
		s.debug.Println("Content-Type: " + dataMime)
		if dataMime != "multipart/form-data" && !dataHasParser && req.Method != "PUT" && req.Method != "HEAD" && req.Method != "OPTIONS" {
			s.debug.Println("Request contains unsupported Media Type:" + dataMime)
			return r.respond(415, "HTTP 415 - Unsupported Media Type:", dataMime)
		}
		req.ContentType = dataMime
	}

	// Content Negotiation
	contentType := "text/turtle"
	acceptList, _ := req.Accept()
	if len(acceptList) > 0 && acceptList[0].SubType != "*" {
		contentType, err = acceptList.Negotiate(serializerMimes...)
		if err != nil {
			s.debug.Println("Accept type not acceptable: " + err.Error())
			return r.respond(406, "HTTP 406 - Accept type not acceptable: "+err.Error())
		}
		req.AcceptType = contentType
	}

	// set ACL Link header
	w.Header().Set("Link", brack(resource.AclURI)+"; rel=\"acl\", "+brack(resource.MetaURI)+"; rel=\"meta\"")

	// generic headers
	w.Header().Set("Accept-Patch", "application/json, application/sparql-update")
	w.Header().Set("Accept-Post", "text/turtle, application/json")
	w.Header().Set("Allow", strings.Join(methodsAll, ", "))
	w.Header().Set("Vary", "Origin")

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

		// set LDP Link headers
		if resource.IsDir {
			w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")
		}
		w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

		// set API Link headers
		w.Header().Add("Link", brack(resource.Base+"/"+SystemPrefix+"/login")+"; rel=\"http://www.w3.org/ns/solid/terms#loginEndpoint\"")
		w.Header().Add("Link", brack(resource.Base+"/"+SystemPrefix+"/logout")+"; rel=\"http://www.w3.org/ns/solid/terms#logoutEndpoint\"")
		w.Header().Add("Link", brack(resource.Base+"/,query")+"; rel=\"http://www.w3.org/ns/solid/terms#twinqlEndpoint\"")
		w.Header().Add("Link", brack(resource.Base+"/,proxy?uri=")+"; rel=\"http://www.w3.org/ns/solid/terms#proxyEndpoint\"")

		return r.respond(200)

	case "GET", "HEAD":
		unlock := lock(resource.File)
		defer unlock()

		var (
			magicType = resource.FileType
			maybeRDF  bool
			glob      bool
			globPath  string
			etag      string
		)

		// check for glob
		glob = false
		if strings.Contains(resource.Obj.Path, "*") {
			glob = true
			path := filepath.Dir(resource.Obj.Path)
			globPath = resource.File
			if path == "." {
				path = ""
			} else {
				path += "/"
			}
			resource, err = req.pathInfo(resource.Base + "/" + path)
			if err != nil {
				return r.respond(500, err)
			}
		}

		if !resource.Exists {
			return r.respondNotFound()
		}

		// First redirect to path + trailing slash if it's missing
		if resource.IsDir && glob == false && !strings.HasSuffix(req.BaseURI(), "/") {
			w.Header().Set(HCType, contentType)
			urlStr := resource.URI
			s.debug.Println("Redirecting to", urlStr)
			http.Redirect(w, req.Request, urlStr, 301)
			return
		}

		// overwrite ACL Link header
		w.Header().Set("Link", brack(resource.AclURI)+"; rel=\"acl\", "+brack(resource.MetaURI)+"; rel=\"meta\"")

		// redirect to app
		if s.Config.Vhosts && !resource.Exists && resource.Base == strings.TrimRight(req.BaseURI(), "/") && contentType == "text/html" && req.Method != "HEAD" {
			w.Header().Set(HCType, contentType)
			urlStr := s.Config.SignUpApp + url.QueryEscape(resource.Obj.Scheme+"://"+resource.Obj.Host+"/"+SystemPrefix+"/accountStatus")
			http.Redirect(w, req.Request, urlStr, 303)
			return
		}

		if resource.IsDir {
			w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")
		}
		w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

		status := 501
		aclStatus, err := acl.AllowRead(resource.URI)
		if aclStatus > 200 || err != nil {
			return r.respond(aclStatus, handleStatusText(aclStatus, err))
		}

		if req.Method == "HEAD" {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", resource.Size))
		}

		etag, err = NewETag(resource.File)
		if err != nil {
			return r.respond(500, err)
		}
		w.Header().Set("ETag", "\""+etag+"\"")

		if !req.ifMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}
		if !req.ifNoneMatch("\""+etag+"\"") && contentType != "text/html" {
			// do not return cached views of dirs for html requests
			return r.respond(304, "304 - Not Modified")
		}

		g := NewGraph(resource.URI)

		if resource.IsDir {
			if len(s.Config.DirIndex) > 0 && contentType == "text/html" {
				magicType = "text/html"
				maybeRDF = false
				for _, dirIndex := range s.Config.DirIndex {
					_, xerr := os.Stat(resource.File + dirIndex)
					status = 200
					if xerr == nil {
						resource, err = req.pathInfo(resource.Base + "/" + resource.Path + dirIndex)
						if err != nil {
							return r.respond(500, err)
						}
						w.Header().Set("Link", brack(resource.MetaURI)+"; rel=\"meta\", "+brack(resource.AclURI)+"; rel=\"acl\"")
						break
					} else if req.Method != "HEAD" {
						//TODO load file manager app from local preference file
						w.Header().Set(HCType, contentType)
						urlStr := s.Config.DirApp + resource.Obj.Scheme + "/" + resource.Obj.Host + "/" + resource.Obj.Path + "?" + req.Request.URL.RawQuery
						s.debug.Println("Redirecting to", urlStr)
						http.Redirect(w, req.Request, urlStr, 303)
						return
					}
				}
			} else {
				w.Header().Add("Link", brack(resource.MetaURI)+"; rel=\"meta\"")

				root := NewResource(resource.URI)
				g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#Directory"))
				g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#Container"))
				g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer"))

				g.AddTriple(root, NewResource("http://www.w3.org/ns/posix/stat#mtime"), NewLiteral(fmt.Sprintf("%d", resource.ModTime.Unix())))
				g.AddTriple(root, NewResource("http://www.w3.org/ns/posix/stat#size"), NewLiteral(fmt.Sprintf("%d", resource.Size)))

				kb := NewGraph(resource.MetaURI)
				kb.ReadFile(resource.MetaFile)
				if kb.Len() > 0 {
					for triple := range kb.IterTriples() {
						var subject Term
						if kb.One(NewResource(resource.MetaURI), nil, nil) != nil {
							subject = NewResource(resource.URI)
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
							res, err := req.pathInfo(resource.Base + "/" + filepath.Dir(resource.Path) + "/" + filepath.Base(file))
							if !res.IsDir && res.Exists && err == nil {
								aclStatus, err = acl.AllowRead(res.URI)
								if aclStatus == 200 && err == nil {
									g.AppendFile(res.File, res.URI)
									g.AddTriple(root, NewResource("http://www.w3.org/ns/ldp#contains"), NewResource(res.URI))
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
						var _s Term
						for _, info := range infos {
							if info != nil {
								// do not list ACLs and Meta files
								if strings.HasSuffix(info.Name(), s.Config.ACLSuffix) || strings.HasSuffix(info.Name(), s.Config.MetaSuffix) {
									continue
								}
								res := resource.URI + info.Name()
								if info.IsDir() {
									res += "/"
								}
								f, err := req.pathInfo(res)
								if err != nil {
									r.respond(500, err)
								}
								if info.IsDir() {
									_s = NewResource(f.URI)
									if !showEmpty {
										g.AddTriple(_s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer"))
										g.AddTriple(_s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#Container"))
									}
									kb := NewGraph(f.URI)
									kb.ReadFile(f.MetaFile)
									if kb.Len() > 0 {
										for _, st := range kb.All(_s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), nil) {
											if st != nil && st.Object != nil {
												g.AddTriple(_s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), st.Object)
											}
										}
									}
								} else {
									_s = NewResource(f.URI)
									if !showEmpty {
										g.AddTriple(_s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#Resource"))
										// add type if RDF resource
										//infoUrl, _ := url.Parse(info.Name())
										guessType := f.FileType

										if guessType == "text/plain" {
											// open file and attempt to read the first line
											// Open an input file, exit on error.
											fd, err := os.Open(f.File)
											if err != nil {
												s.debug.Println("GET find mime type error:" + err.Error())
											}
											defer fd.Close()

											scanner := bufio.NewScanner(fd)

											// stop after the first line
											for scanner.Scan() {
												if strings.HasPrefix(scanner.Text(), "@prefix") || strings.HasPrefix(scanner.Text(), "@base") {
													kb := NewGraph(f.URI)
													kb.ReadFile(f.File)
													if kb.Len() > 0 {
														for _, st := range kb.All(NewResource(f.URI), NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), nil) {
															if st != nil && st.Object != nil {
																g.AddTriple(_s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), st.Object)
															}
														}
													}
												}
												break
											}
											// log potential errors
											if err := scanner.Err(); err != nil {
												s.debug.Println("GET scan err: " + scanner.Err().Error())
											}
										}
									}
								}
								if !showEmpty {
									g.AddTriple(_s, NewResource("http://www.w3.org/ns/posix/stat#mtime"), NewLiteral(fmt.Sprintf("%d", info.ModTime().Unix())))
									g.AddTriple(_s, NewResource("http://www.w3.org/ns/posix/stat#size"), NewLiteral(fmt.Sprintf("%d", info.Size())))
								}
								if showContainment {
									g.AddTriple(root, NewResource("http://www.w3.org/ns/ldp#contains"), _s)
								}
							}
						}
					}
				}
				status = 200
				maybeRDF = true
			}
		} else {
			magicType = resource.FileType
			maybeRDF = resource.MaybeRDF
			if len(mimeRdfExt[resource.Extension]) > 0 {
				maybeRDF = true
			}
			if !maybeRDF && magicType == "text/plain" {
				maybeRDF = true
			}
			s.debug.Println("Setting CType to:", magicType)
			status = 200

			if req.Method == "GET" && strings.Contains(contentType, "text/html") {
				// delete ETag to force load the app
				w.Header().Del("ETag")
				w.Header().Set("Link", brack(resource.MetaURI)+"; rel=\"meta\", "+brack(resource.AclURI)+"; rel=\"acl\"")
				if maybeRDF {
					w.Header().Set(HCType, contentType)
					s.debug.Println("Rendering data app")
					app, err := apps.DataApp()
					if err != nil {
						return r.respond(500, "")
					}
					return r.respond(200, app)
				}
				w.Header().Set(HCType, magicType)
				w.WriteHeader(200)
				f, err := os.Open(resource.File)
				if err == nil {
					defer func() {
						if err := f.Close(); err != nil {
							s.debug.Println("GET os.Open err: " + err.Error())
						}
					}()
					io.Copy(w, f)
				}
				return
			}
		}

		if status != 200 {
			return r.respond(status)
		}

		if req.Method == "HEAD" {
			w.Header().Set(HCType, contentType)
			return r.respond(status)
		}

		if !maybeRDF && len(magicType) > 0 {
			w.Header().Set(HCType, magicType)

			if status == 200 {
				f, err := os.Open(resource.File)
				if err == nil {
					defer func() {
						if err := f.Close(); err != nil {
							s.debug.Println("GET f.Close err:" + err.Error())
						}
					}()
					io.Copy(w, f)
				}
			} else {
				w.WriteHeader(status)
			}
			return
		}

		if maybeRDF {
			g.ReadFile(resource.File)
			w.Header().Set(HCType, contentType)
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
		aclAppend, err := acl.AllowAppend(resource.URI)
		if aclAppend > 200 || err != nil {
			// check if we can write then
			aclWrite, err := acl.AllowWrite(resource.URI)
			if aclWrite > 200 || err != nil {
				return r.respond(aclWrite, handleStatusText(aclWrite, err))
			}
		}

		etag, _ := NewETag(resource.File)
		if !req.ifMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}
		if !req.ifNoneMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}

		if dataHasParser {
			s.debug.Println("Preparing to PATCH resource", resource.URI, "with file", resource.File)
			buf, _ := ioutil.ReadAll(req.Body)
			body := ioutil.NopCloser(bytes.NewBuffer(buf))

			req.Body.Close()

			if req.Header.Get("Content-Length") == "0" || len(buf) == 0 {
				errmsg := "Could not patch resource. No SPARQL statements found in the request."
				s.debug.Println(errmsg)
				return r.respond(400, errmsg)
			}

			g := NewGraph(resource.URI)
			g.ReadFile(resource.File)

			switch dataMime {
			case "application/json":
				g.JSONPatch(body)
			case "application/sparql-update":
				sparql := NewSPARQLUpdate(g.URI())
				sparql.Parse(body)
				ecode, err := g.SPARQLUpdate(sparql)
				if err != nil {
					return r.respond(ecode, "Error processing SPARQL Update: "+err.Error())
				}
			default:
				if dataHasParser {
					g.Parse(body, dataMime)
				}
			}

			if !resource.Exists {
				err = os.MkdirAll(_path.Dir(resource.File), 0755)
				if err != nil {
					s.debug.Println("PATCH MkdirAll err: " + err.Error())
					return r.respond(500, err)
				}
			}
			f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0664)
			if err != nil {
				s.debug.Println("PATCH os.OpenFile err: " + err.Error())
				return r.respond(500, err)
			}
			defer f.Close()

			err = g.WriteFile(f, "text/turtle")
			if err != nil {
				s.debug.Println("PATCH g.WriteFile err: " + err.Error())
				return r.respond(500, err)
			}
			s.debug.Println("Succefully PATCHed resource", resource.URI)
			onUpdateURI(resource.URI)
			onUpdateURI(resource.ParentURI)

			return r.respond(200)
		}

	case "POST":
		unlock := lock(resource.File)
		defer unlock()
		updateURI := resource.URI

		// check append first
		aclAppend, err := acl.AllowAppend(resource.URI)
		if aclAppend > 200 || err != nil {
			// check if we can write then
			aclWrite, err := acl.AllowWrite(resource.URI)
			if aclWrite > 200 || err != nil {
				return r.respond(aclWrite, handleStatusText(aclWrite, err))
			}
		}
		err = nil

		etag, _ := NewETag(resource.File)
		if !req.ifMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}
		if !req.ifNoneMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}

		// LDP
		isNew := false
		if resource.IsDir && dataMime != "multipart/form-data" {
			link := ParseLinkHeader(req.Header.Get("Link")).MatchRel("type")
			slug := req.Header.Get("Slug")

			uuid := NewUUID()
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
				st, err := os.Stat(resource.File + slug)
				//@@TODO append a random string

				if st != nil && !os.IsNotExist(err) {
					slug += "-" + uuid
				}
			} else {
				slug = uuid
			}
			resource.Path += slug

			if len(link) > 0 && link == "http://www.w3.org/ns/ldp#BasicContainer" {
				if !strings.HasSuffix(resource.Path, "/") {
					resource.Path += "/"
				}
				resource, err = req.pathInfo(resource.Base + "/" + resource.Path)
				if err != nil {
					s.debug.Println("POST LDPC req.pathInfo err: " + err.Error())
					return r.respond(500, err)
				}

				w.Header().Set("Location", resource.URI)
				w.Header().Set("Link", brack(resource.MetaURI)+"; rel=\"meta\", "+brack(resource.AclURI)+"; rel=\"acl\"")
				w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
				w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")

				err = os.MkdirAll(resource.File, 0755)
				if err != nil {
					s.debug.Println("POST LDPC os.MkdirAll err: " + err.Error())
					return r.respond(500, err)
				}
				s.debug.Println("Created dir " + resource.File)

				buf := new(bytes.Buffer)
				buf.ReadFrom(req.Body)
				if buf.Len() > 0 {
					f, err := os.OpenFile(resource.MetaFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
					if err != nil {
						s.debug.Println("POST LDPC os.OpenFile err: " + err.Error())
						return r.respond(500, err)
					}
					defer f.Close()
					_, err = io.Copy(f, buf)
					if err != nil {
						s.debug.Println("POST io.Copy err: " + err.Error())
					}
				}

				w.Header().Set("Location", resource.URI)
				onUpdateURI(resource.URI)
				onUpdateURI(resource.ParentURI)
				return r.respond(201)
			}

			resource, err = req.pathInfo(resource.Base + "/" + resource.Path)
			if err != nil {
				s.debug.Println("POST LDPR req.pathInfo err: " + err.Error())
				return r.respond(500, err)
			}
			w.Header().Set("Location", resource.URI)
			w.Header().Set("Link", brack(resource.MetaURI)+"; rel=\"meta\", "+brack(resource.AclURI)+"; rel=\"acl\"")
			// LDP header
			w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
			isNew = true
		}

		if !resource.Exists {
			err = os.MkdirAll(_path.Dir(resource.File), 0755)
			if err != nil {
				s.debug.Println("POST MkdirAll err: " + err.Error())
				return r.respond(500, err)
			}
			s.debug.Println("Created resource " + _path.Dir(resource.File))
		}

		if dataMime == "multipart/form-data" {
			err := req.ParseMultipartForm(100000)
			if err != nil {
				s.debug.Println("POST parse multipart data err: " + err.Error())
			} else {
				m := req.MultipartForm
				for elt := range m.File {
					files := m.File[elt]
					for i := range files {
						file, err := files[i].Open()
						defer file.Close()
						if err != nil {
							s.debug.Println("POST multipart/form f.Open err: " + err.Error())
							return r.respond(500, err)
						}
						newFile := ""
						if filepath.Base(resource.Path) == files[i].Filename {
							newFile = resource.File
						} else {
							newFile = resource.File + files[i].Filename
						}
						dst, err := os.OpenFile(newFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
						defer dst.Close()
						if err != nil {
							s.debug.Println("POST multipart/form os.Create err: " + err.Error())
							return r.respond(500, err)
						}
						if _, err := io.Copy(dst, file); err != nil {
							s.debug.Println("POST multipart/form io.Copy err: " + err.Error())
							return r.respond(500, err)
						}
						location := &url.URL{Path: files[i].Filename}
						w.Header().Add("Location", resource.URI+location.String())
					}
				}
				onUpdateURI(resource.URI)
				return r.respond(201)
			}
		} else {
			if !resource.Exists {
				isNew = true
			}
			if resource.IsDir {
				resource.File = resource.File + "/" + s.Config.MetaSuffix
			}

			if dataHasParser {
				g := NewGraph(resource.URI)
				g.ReadFile(resource.File)

				switch dataMime {
				case "application/json":
					g.JSONPatch(req.Body)
				case "application/sparql-update":
					sparql := NewSPARQLUpdate(g.URI())
					sparql.Parse(req.Body)
					ecode, err := g.SPARQLUpdate(sparql)
					if err != nil {
						println(err.Error())
						return r.respond(ecode, "Error processing SPARQL Update: "+err.Error())
					}
				default:
					g.Parse(req.Body, dataMime)
				}
				f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					s.debug.Println("POST os.OpenFile err: " + err.Error())
					return r.respond(500, err.Error())
				}
				defer f.Close()
				if g.Len() > 0 {
					err = g.WriteFile(f, "text/turtle")
					if err != nil {
						s.debug.Println("POST g.WriteFile err: " + err.Error())
					} else {
						s.debug.Println("Wrote resource file: " + resource.File)
					}
				}
			} else {
				f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					s.debug.Println("POST os.OpenFile err: " + err.Error())
					return r.respond(500, err.Error())
				}
				defer f.Close()
				_, err = io.Copy(f, req.Body)
				if err != nil {
					s.debug.Println("POST os.OpenFile err: " + err.Error())
					return r.respond(500, err.Error())
				}
			}

			onUpdateURI(updateURI)
			if updateURI != resource.ParentURI {
				onUpdateURI(resource.ParentURI)
			}
			if isNew {
				return r.respond(201)
			}
			return r.respond(200)
		}

	case "PUT":
		unlock := lock(resource.File)
		defer unlock()

		// LDP header
		w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

		// check append first
		aclAppend, err := acl.AllowAppend(resource.URI)
		if aclAppend > 200 || err != nil {
			// check if we can write then
			aclWrite, err := acl.AllowWrite(resource.URI)
			if aclWrite > 200 || err != nil {
				return r.respond(aclWrite, handleStatusText(aclWrite, err))
			}
		}

		etag, _ := NewETag(resource.File)
		if !req.ifMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}
		if !req.ifNoneMatch("\"" + etag + "\"") {
			return r.respond(412, "412 - Precondition Failed")
		}

		isNew := true
		if resource.Exists {
			isNew = false
		}

		// LDP PUT should be merged with LDP POST into a common LDP "method" switch
		link := ParseLinkHeader(req.Header.Get("Link")).MatchRel("type")
		if len(link) > 0 && link == "http://www.w3.org/ns/ldp#BasicContainer" {
			err := os.MkdirAll(resource.File, 0755)
			if err != nil {
				s.debug.Println("PUT MkdirAll err: " + err.Error())
				return r.respond(500, err)
			}
			// refresh resource and set the right headers
			resource, err = req.pathInfo(resource.URI)
			w.Header().Set("Link", brack(resource.MetaURI)+"; rel=\"meta\", "+brack(resource.AclURI)+"; rel=\"acl\"")
			// LDP header
			w.Header().Add("Link", brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

			onUpdateURI(resource.URI)
			onUpdateURI(resource.ParentURI)
			return r.respond(201)
		}
		err = os.MkdirAll(_path.Dir(resource.File), 0755)
		if err != nil {
			s.debug.Println("PUT MkdirAll err: " + err.Error())
			return r.respond(500, err)
		}

		f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			s.debug.Println("PUT os.OpenFile err: " + err.Error())
			if resource.IsDir {
				w.Header().Add("Link", brack(resource.URI)+"; rel=\"describedby\"")
				return r.respond(406, "406 - Cannot use PUT on a directory.")
			}
			return r.respond(500, err)
		}
		defer f.Close()

		_, err = io.Copy(f, req.Body)
		if err != nil {
			s.debug.Println("PUT io.Copy err: " + err.Error())
		}

		if err != nil {
			return r.respond(500, err)
		}

		w.Header().Set("Location", resource.URI)

		onUpdateURI(resource.URI)
		onUpdateURI(resource.ParentURI)
		if isNew {
			return r.respond(201)
		}
		return r.respond(200)

	case "DELETE":
		unlock := lock(resource.Path)
		defer unlock()

		aclWrite, err := acl.AllowWrite(resource.URI)
		if aclWrite > 200 || err != nil {
			return r.respond(aclWrite, handleStatusText(aclWrite, err))
		}

		if len(resource.Path) == 0 {
			return r.respond(500, "500 - Cannot DELETE root (/)")
		}
		// remove ACL and meta files first
		if resource.File != resource.AclFile {
			_ = os.Remove(resource.AclFile)
		}
		if resource.File != resource.MetaFile {
			_ = os.Remove(resource.MetaFile)
		}
		err = os.Remove(resource.File)
		if err != nil {
			if os.IsNotExist(err) {
				return r.respondNotFound()
			}
			return r.respond(500, err)
		}
		_, err = os.Stat(resource.File)
		if err == nil {
			return r.respond(409, err)
		}
		onDeleteURI(resource.URI)
		onUpdateURI(resource.ParentURI)
		return

	case "MKCOL":
		unlock := lock(resource.File)
		defer unlock()

		aclWrite, err := acl.AllowWrite(resource.URI)
		if aclWrite > 200 || err != nil {
			return r.respond(aclWrite, handleStatusText(aclWrite, err))
		}

		err = os.MkdirAll(resource.File, 0755)
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
		onUpdateURI(resource.URI)
		onUpdateURI(resource.ParentURI)
		return r.respond(201)

	case "COPY", "MOVE", "LOCK", "UNLOCK":
		aclWrite, err := acl.AllowWrite(resource.URI)
		if aclWrite > 200 || err != nil {
			return r.respond(aclWrite, handleStatusText(aclWrite, err))
		}
		s.webdav.ServeHTTP(w, req.Request)

	default:
		return r.respond(405, "405 - Method Not Allowed:", req.Method)
	}
	return
}
