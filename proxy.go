package gold

import (
	"github.com/elazarl/goproxy"
	"net/http"
)

func NewProxy() *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		r.Header.Set("Access-Control-Allow-Credentials", "true")
		r.Header.Set("Access-Control-Expose-Headers", "User, Triples, Location, Link, Vary, Last-Modified, Content-Length")
		r.Header.Set("Access-Control-Max-Age", "60")
		return r
	})
	return proxy
}
