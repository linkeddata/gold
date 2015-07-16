package gold

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"net/http"

	"github.com/elazarl/goproxy"
)

var (
	proxy = goproxy.NewProxyHttpServer()
)

func init() {
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		r.Header.Set("Access-Control-Allow-Credentials", "true")
		r.Header.Set("Access-Control-Allow-Origin", "*")
		r.Header.Set("Access-Control-Expose-Headers", "User, Triples, Location, Link, Vary, Last-Modified, Content-Length")
		r.Header.Set("Access-Control-Max-Age", "60")
		return r
	})
}

func HijackProxy(w http.ResponseWriter, req *http.Request, s *Server) {
	if len(s.Config.AgentCert) > 0 && len(s.Config.AgentKey) > 0 && (req.Method == "GET" || req.Method == "HEAD") {
		s.debug.Println("Hijacking proxy")

		s.debug.Println("Loading keypair from:", s.Config.AgentCert, s.Config.AgentKey)
		cert, err := tls.LoadX509KeyPair(s.Config.AgentCert, s.Config.AgentKey)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		conf := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
			Rand:               rand.Reader,
		}

		agenth := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: conf,
			},
		}
		s.debug.Println("Auth proxy for:", req.URL.String())
		request, err := http.NewRequest(req.Method, req.URL.String(), nil)
		if err != nil {
			s.debug.Println("Error in request", err.Error())
			w.WriteHeader(500)
			return
		}
		request.Header = req.Header
		response, err := agenth.Do(request)
		if err != nil {
			s.debug.Println("Error in response", err.Error())
			w.WriteHeader(500)
			return
		}
		defer response.Body.Close()
		// write headers
		response.Header.Del("User")
		for h := range response.Header {
			// s.debug.Println(response.Header.Get(h))
			w.Header().Add(h, response.Header.Get(h))
		}
		// w.Header().Add("Content-Type", response.Header.Get("Content-Type"))
		// w.Header().Add("User", response.Header.Get("User"))
		w.WriteHeader(response.StatusCode)

		// write contents
		io.Copy(w, response.Body)
	}
}
