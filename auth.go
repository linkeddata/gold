package gold

import (
	"net"
	"net/http"
	"time"
)

func (req *httpRequest) authn(w http.ResponseWriter) string {
	user := req.userCookie()
	if len(user) > 0 {
		req.Server.debug.Println("Cookie authentication successful for User: " + user)
		return user
	}

	user, _ = WebIDTLSAuth(req.TLS)
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

func (req *httpRequest) userCookie() string {
	cookie, err := req.Cookie("Session")
	if err == nil {
		value := make(map[string]string)
		if err = req.Server.cookie.Decode("Session", cookie.Value, &value); err == nil {
			req.Server.debug.Println("The value of User is " + value["user"])
			return value["user"]
		}
		req.Server.debug.Println("Error decoding cookie: " + err.Error())
	}
	req.Server.debug.Println("Error reading cookie: " + err.Error())
	return ""
}

func (srv *Server) userCookieSet(w http.ResponseWriter, user string) error {
	value := map[string]string{
		"user": user,
	}
	encoded, err := srv.cookie.Encode("Session", value)
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Expires: time.Now().Add(srv.Config.CookieAge),
		Name:    "Session",
		Path:    "/",
		Value:   encoded,
	}
	http.SetCookie(w, cookie)
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
