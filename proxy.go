package gold

import (
	"net/http"

	"github.com/elazarl/goproxy"
)

var (
	proxy = goproxy.NewProxyHttpServer()
)

func init() {
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if r == nil {
			return r
		}
		r.Header.Set("Access-Control-Allow-Credentials", "true")
		r.Header.Set("Access-Control-Expose-Headers", "User, Location, Link, Vary, Last-Modified, WWW-Authenticate, Content-Length, Content-Type, Accept-Patch, Accept-Post, Allow, Updates-Via, Ms-Author-Via")
		r.Header.Set("Access-Control-Max-Age", "60")
		// Drop connection to allow for HTTP/2 <-> HTTP/1.1 compatibility
		r.Header.Del("Connection")
		return r
	})
}
