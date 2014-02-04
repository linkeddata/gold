package gold

import (
	"flag"
	"fmt"
	"github.com/presbrey/magicmime"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	_path "path"
	"strings"
)

const HCType = "Content-Type"

var (
	debug    = flag.Bool("debug", false, "output extra logging")
	dirIndex = flag.String("dirIndex", "index.html", "filename used for directory indexing (empty to disable)")
	root     = flag.String("root", ".", "path to file storage root")
	skin     = flag.String("skin", "tabulator", "default view for HTML clients")
	stream   = flag.Bool("stream", false, "stream responses (experimental)")
	vhosts   = flag.Bool("vhosts", false, "append serverName to path on disk")

	methodsAll = []string{
		"GET", "PUT", "POST", "OPTIONS", "HEAD", "MKCOL", "DELETE", "PATCH",
	}

	magic *magicmime.Magic
)

func init() {
	var err error

	magic, err = magicmime.NewMagic()
	if err != nil {
		panic(err)
	}
}

type httpRequest http.Request

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
	user := ""
	if req.TLS != nil && req.TLS.HandshakeComplete {
		user, _ = WebIDTLSAuth(req.TLS)
	}
	if len(user) == 0 {
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		remoteAddr := net.ParseIP(host)
		user = "dns:" + remoteAddr.String()
	}
	return user
}

type Handler struct{ http.Handler }

func (h Handler) ServeHTTP(w http.ResponseWriter, req0 *http.Request) {
	var (
		err error

		data, path string
	)

	defer func() {
		req0.Body.Close()
	}()
	req := (*httpRequest)(req0)
	user := req.Auth()
	w.Header().Set("User", user)

	dataMime := req.Header.Get(HCType)
	dataMime = strings.Split(dataMime, ";")[0]
	dataHasParser := len(mimeParser[dataMime]) > 0
	if len(dataMime) > 0 && !dataHasParser && req.Method != "PUT" {
		w.WriteHeader(415)
		fmt.Fprintln(w, "Unsupported Media Type:", dataMime)
		return
	}

	// Content Negotiation
	contentType := "text/turtle"
	acceptList, _ := req.Accept()
	if len(acceptList) > 0 && acceptList[0].SubType != "*" {
		contentType, err = acceptList.Negotiate(serializerMimes...)
		if err != nil {
			w.WriteHeader(406) // Not Acceptable
			fmt.Fprintln(w, err)
			return
		}
	}

	// CORS
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "60")
	w.Header().Set("MS-Author-Via", "DAV, SPARQL")

	g := NewGraph(req.BaseURI())
	if *debug {
		log.Printf("user=%s req=%+v\n%+v\n\n", user, req, g)
	}
	path = g.Path()

	// TODO: WAC
	origin := ""
	origins := req.Header["Origin"] // all CORS requests
	if len(origins) > 0 {
		origin = origins[0]
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

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
		w.WriteHeader(200)
		return

	case "GET", "HEAD":
		var (
			magicType string
			maybeRDF  bool
		)

		status := 501
		stat, serr := os.Stat(path)
		switch {
		case os.IsNotExist(serr):
			status = 404
		case stat.IsDir():
			if len(*dirIndex) > 0 && contentType == "text/html" {
				_, xerr := os.Stat(path + "/" + *dirIndex)
				if xerr == nil {
					status = 200
					magicType = "text/html"
					path = _path.Join(path, *dirIndex)
				}
			}
		default:
			status = 200
			magicType, _ = magic.TypeByFile(path)
			maybeRDF = magicType == "text/plain"
		}

		if status != 200 {
			if req.Method == "GET" && contentType == "text/html" {
				w.Header().Set(HCType, contentType)
				w.WriteHeader(200)
				fmt.Fprint(w, Skins[*skin])
				return
			}
			w.WriteHeader(status)
			return
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
					defer f.Close()
					io.Copy(w, f)
				}
			}
			return
		}

		if req.Method == "HEAD" {
			w.WriteHeader(status)
			return
		}

		if *stream {
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
			w.WriteHeader(500)
			fmt.Fprint(w, err)
		} else if len(data) > 0 {
			fmt.Fprint(w, data)
		}

	case "PATCH", "POST", "PUT":
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

		os.MkdirAll(_path.Dir(path), 0755)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprint(w, err)
			return
		}
		defer f.Close()
		if dataHasParser {
			err = g.WriteFile(f, "")
		} else {
			_, err = io.Copy(f, req.Body)
		}
		if err != nil {
			w.WriteHeader(500)
		} else if req.Method == "PUT" {
			w.WriteHeader(201)
		}

	case "DELETE":
		err := os.Remove(path)
		if err != nil {
			if os.IsNotExist(err) {
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(500)
			fmt.Fprint(w, err)
		} else {
			_, err := os.Stat(path)
			if err == nil {
				w.WriteHeader(409)
			}
		}

	case "MKCOL":
		err := os.MkdirAll(path, 0755)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprint(w, err)
			return
		} else {
			_, err := os.Stat(path)
			if err != nil {
				w.WriteHeader(409)
				fmt.Fprint(w, err)
			}
		}
		w.WriteHeader(201)

	default:
		w.WriteHeader(405)
		fmt.Fprintln(w, "Method Not Allowed:", req.Method)

	}
	return
}
