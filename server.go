package gold

import (
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

func (s *Server) GraphPath(g AnyGraph) (path string) {
	lst := strings.SplitN(g.URI(), "://", 2)
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
	var (
		err error

		data, path string
	)

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

	g := NewGraph(req.BaseURI())
	if Debug {
		log.Printf("user=%s req=%+v\n%+v\n\n", user, req, g)
	}
	path = h.GraphPath(g)
	unlock := lock(path)
	defer unlock()

	// TODO: WAC
	origin := ""
	origins := req.Header["Origin"] // all CORS requests
	if len(origins) > 0 {
		origin = origins[0]
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	w.Header().Set("Link", brack(acl.Uri())+"; rel=acl")

	base, _ := url.Parse(req.BaseURI())

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
		var (
			magicType string
			maybeRDF  bool
			glob      bool
			globPath  string
			etag      string
		)

		// check for glob
		if strings.LastIndex(path, "*") == len(path)-1 {
			glob = true
			globPath = path
			path = strings.TrimRight(path, "*")
			// TODO: use Depth header (WebDAV)
		} else {
			glob = false
		}

		status := 501
		if !acl.AllowRead() {
			return r.respond(403)
		}

		if status != 200 {
			if req.Method == "GET" && contentType == "text/html" {
				w.Header().Set(HCType, contentType)
				return r.respond(200, Skins[Skin])
			}
		}

		if glob {
			matches, err := filepath.Glob(globPath)
			if err == nil {
				for _, file := range matches {
					stat, serr := os.Stat(file)
					if !stat.IsDir() && serr == nil {
						g.AppendFile(file, filepath.Base(file))
					}
				}
				status = 200
			} else {
				if Debug {
					log.Printf("%+v\n", err)
				}
			}
		} else {
			stat, serr := os.Stat(path)
			switch {
			case os.IsNotExist(serr):
				status = 404
			case stat.IsDir():
				if len(DirIndex) > 0 && contentType == "text/html" {
					for _, dirIndex := range DirIndex {
						_, xerr := os.Stat(path + "/" + dirIndex)
						if xerr == nil {
							status = 200
							magicType = "text/html"
							path = _path.Join(path, dirIndex)
							break
						}
					}
				} else {
					// TODO: RDF
					if infos, err := ioutil.ReadDir(path); err == nil {
						magicType = "text/turtle"

						root := NewResource(req.BaseURI())
						g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#Directory"))
						g.AddTriple(root, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer"))

						if !strings.HasSuffix(path, "/") {
							path = path + "/"
						}
						metaUrl, _ := url.Parse(METASuffix)
						kb := NewGraph(base.ResolveReference(metaUrl).String())
						kb.ReadFile(path + METASuffix)
						if kb.Len() > 0 {
							for triple := range kb.IterTriples() {
								var subject Term
								if kb.One(NewResource(strings.TrimLeft(path, "./")+METASuffix), nil, nil) != nil {
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
								if info.IsDir() {
									s = NewResource(info.Name() + "/")
									if !showEmpty {
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#Directory"))
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer"))
									}
								} else {
									s = NewResource(info.Name())

									if !showEmpty {
										g.AddTriple(s, NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/posix/stat#File"))
										// add type if RDF resource
										infoUrl, _ := url.Parse(info.Name())
										kb := NewGraph(base.ResolveReference(infoUrl).String())
										kb.ReadFile(path + info.Name())
										if kb.Len() > 0 {
											st := kb.One(NewResource(base.ResolveReference(infoUrl).String()), NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), nil)
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
				status = 200
				magicType, _ = magic.TypeByFile(path)
				maybeRDF = magicType == "text/plain"
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
				switch path[len(path)-5:] {
				case ".html":
					magicType = "text/html"
				}
			}
			w.Header().Set(HCType, magicType)
			w.WriteHeader(status)
			if req.Method == "HEAD" {
				w.WriteHeader(status)
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
			log.Println(err)
			return r.respond(500, err)
		} else if len(data) > 0 {
			fmt.Fprint(w, data)
		}

	case "PATCH", "POST", "PUT":
		// check append first
		if !acl.AllowAppend() && !acl.AllowWrite() {
			return r.respond(403)
		}

		etag, _ := NewETag(path)
		if !req.ifMatch(etag) {
			return r.respond(412, "Precondition Failed")
		}
		if !req.ifNoneMatch(etag) {
			return r.respond(412, "Precondition Failed")
		}

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

				if link == "http://www.w3.org/ns/ldp#Resource" {
					newLoc, _ := url.Parse(slug)
					w.Header().Set("Location", base.String()+newLoc.String())
				} else if link == "http://www.w3.org/ns/ldp#BasicContainer" {
					if !strings.HasSuffix(path, "/") {
						path = path + "/"
						slug = slug + "/"
					}
					newLoc, _ := url.Parse(slug)
					location := base.String() + newLoc.String()
					w.Header().Set("Location", location)

					err = os.MkdirAll(path, 0755)
					if err != nil {
						return r.respond(500, err)
					}

					path = path + METASuffix
					metaUrl, _ := url.Parse(slug + METASuffix)

					w.Header().Set("Link", "<"+base.String()+metaUrl.String()+">; rel=meta")

					//Replace the subject with the dir path instead of the meta file path
					if dataHasParser {
						mg := NewGraph(base.ResolveReference(metaUrl).String())
						mg.Parse(req.Body, dataMime)
						for triple := range mg.IterTriples() {
							subject := NewResource(path)
							g.AddTriple(subject, triple.Predicate, triple.Object)
						}

						f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
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
		if !acl.AllowWrite() && !acl.AllowAppend() {
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
	case "MKCOL":
		if !acl.AllowWrite() && !acl.AllowAppend() {
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
