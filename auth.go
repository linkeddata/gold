package gold

import (
	"net"
	"net/http"
)

func (req *httpRequest) Auth(w http.ResponseWriter) string {
	user := ReadCookie(w, req)
	if len(user) == 0 {
		user, _ = WebIDTLSAuth(req.TLS)
		if len(user) == 0 {
			host, _, _ := net.SplitHostPort(req.RemoteAddr)
			remoteAddr := net.ParseIP(host)
			user = "dns:" + remoteAddr.String()
		} else {
			req.Server.debug.Println("WebID-TLS authentication successful for User: " + user)
			// start session
			SetCookie(w, user)
		}
	} else {
		req.Server.debug.Println("Cookie authentication successful for User: " + user)
	}
	req.Server.debug.Println("Request User: " + user)
	return user
}
