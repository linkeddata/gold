package gold

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
)

var (
	debug = flag.Bool("debug", false, "output extra logging")

	methodsAll = []string{
		"GET", "PUT", "POST", "OPTIONS", "HEAD", "MKCOL", "DELETE", "PATCH",
	}
)

type httpRequest http.Request

func (req httpRequest) BaseURI() string {
	scheme := "http"
	if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
		scheme += "s"
	}
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		log.Printf("SplitHostPort(%q) error: %s", req.Host, err)
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
		data []byte
		err  error

		req = (*httpRequest)(req0)
	)

	g := NewGraph(req.BaseURI())
	user := req.Auth()
	w.Header().Set("User", user)

	defer func() {
		req.Body.Close()
	}()
	dataMime := req.Header.Get("Content-Type")
	dataMime = strings.Split(dataMime, ";")[0]
	dataParser := parserMime[dataMime]
	if len(dataMime) > 0 && len(dataParser) == 0 {
		w.WriteHeader(415)
		// TODO: RDF errors
		fmt.Fprintln(w, "Unsupported Media Type:", dataMime)
		return
	} else if len(dataMime) > 0 {
		data, err = ioutil.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(400) // Bad Request
			fmt.Fprintln(w, err)
			return
		}
	}

	// Content Negotiation
	acceptList, _ := req.Accept()
	cMime, err := acceptList.Negotiate(serializerMimes...)
	if err != nil {
		w.WriteHeader(406) // Not Acceptable
		fmt.Fprintln(w, err)
	}

	// CORS
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "60")
	w.Header().Set("MS-Author-Via", "DAV, SPARQL")

	// TODO: check WAC
	origin := ""
	origins := req.Header["Origin"] // all CORS requests
	if len(origins) > 0 {
		origin = origins[0]
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	if *debug {
		log.Printf("(%s) %s: %q\n%+v\n", user, req.Method, string(data), g)
		log.Printf("(%s) %+v\n", user, req)
	}

	switch req.Method {
	case "OPTIONS":
		w.Header().Set("Accept-Patch", "application/json")
		w.Header().Set("Accept-Post", "text/turtle,application/json")

		// TODO: check WAC
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
		if req.Method != "GET" {
			w.WriteHeader(200)
			return
		}
		if cMime == "text/html" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			fmt.Fprint(w, tabulatorSkin)
			return
		}
		w.WriteHeader(204)
		return

	case "PATCH":
	case "POST":
	case "PUT":
	case "DELETE":
	case "MKCOL":
	}

	w.WriteHeader(405)
	fmt.Fprintln(w, "Method Not Allowed:", req.Method)
	return
}
