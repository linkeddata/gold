package gold

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/url"

	"fmt"
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

func (r *httpRequest) IsAgentRequest(s *Server) bool {
	if len(s.Config.AgentWebID) > 0 {
		if p, err := url.Parse(s.Config.AgentWebID); err == nil {
			if r.RequestURI == p.Path {
				return true
			}
		}
	}
	return false
}

// NewAgentIdentity generates the agent's WebID and cert
func NewAgentIdentity(s *Server) error {
	agentGraph, agentPrv, _, err := NewWebIDProfileWithKeys(s.Config.AgentWebID)
	// create cert
	agentCert, err := NewRSADerCert(s.Config.AgentWebID, "Minion", agentPrv)
	if err != nil {
		return err
	}
	// serialize
	AgentProfile, err = agentGraph.Serialize("text/turtle")
	if err != nil {
		return err
	}
	AgentKey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(agentPrv),
	})
	AgentCert = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: agentCert,
	})
	return nil
}

func DelegationProxy(w http.ResponseWriter, req *http.Request, s *Server) {
	s.debug.Println("Method requested:", req.Method)
	if req.Method != "GET" && req.Method != "HEAD" {
		w.WriteHeader(405)
		fmt.Fprint(w, "405 - Method Not Allowed:"+req.Method)
		return
	}
	if len(AgentCert) > 0 {
		s.debug.Println("Hijacking proxy")
		cert, err := tls.X509KeyPair(AgentCert, AgentKey)
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
		// defer request.Body.Close()
		defer func() {
			response.Body.Close()
		}()
		// do not forward User heder
		response.Header.Del("User")
		// write headers
		for h := range response.Header {
			// s.debug.Println(response.Header.Get(h))
			w.Header().Add(h, response.Header.Get(h))
		}
		// w.Header().Add("Content-Type", response.Header.Get("Content-Type"))
		// w.Header().Add("User", response.Header.Get("User"))
		w.WriteHeader(response.StatusCode)

		// write contents
		io.Copy(w, response.Body)
		return
	}
}
