package gold

import (
	"net"
	"net/http"
	"time"
)

func (req *httpRequest) authn(w http.ResponseWriter) string {
	user, err := req.userCookie()
	if err != nil {
		req.Server.debug.Println("userCookie error:", err)
	}
	if len(user) > 0 {
		req.Server.debug.Println("Cookie authentication successful for User: " + user)
		return user
	}

	user, err = WebIDTLSAuth(req.TLS)
	if err != nil {
		req.Server.debug.Println("WebID-TLS error:", err)
	}
	if len(user) > 0 {
		req.Server.debug.Println("WebID-TLS authentication successful for User: " + user)
		req.Server.userCookieSet(w, user)
		return user
	}

	host, _, _ := net.SplitHostPort(req.RemoteAddr)
	remoteAddr := net.ParseIP(host)
	user = "dns:" + remoteAddr.String()
	req.Server.debug.Println("Unauthenticated User: " + user)
	return user
}

func (req *httpRequest) userCookie() (string, error) {
	value := make(map[string]string)
	cookie, err := req.Cookie("Session")
	if err == nil {
		err = req.Server.cookie.Decode("Session", cookie.Value, &value)
	}
	if err == nil {
		return value["user"], nil
	}
	return "", err
}

func (srv *Server) userCookieSet(w http.ResponseWriter, user string) error {
	value := map[string]string{
		"user": user,
	}
	encoded, err := srv.cookie.Encode("Session", value)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Expires: time.Now().Add(srv.Config.CookieAge),
		Name:    "Session",
		Path:    "/",
		Value:   encoded,
	})
	return nil
}

func (srv *Server) userCookieDelete(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "Session",
		Value:  "deleted",
		Path:   "/",
		MaxAge: -1,
	})
}
