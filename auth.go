package gold

import (
	"fmt"
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
		if err == nil {
			return value["user"], nil
		}
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
	t := time.Duration(srv.Config.CookieAge) * time.Hour
	http.SetCookie(w, &http.Cookie{
		Expires: time.Now().Add(t),
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

// NewSecureToken generates a signed token to be used during account recovery
func NewSecureToken(values map[string]string, duration time.Duration, s *Server) (string, error) {
	valid := time.Now().Add(duration).Unix()
	values["valid"] = fmt.Sprintf("%d", valid)
	token, err := s.cookie.Encode("Recovery", values)
	if err != nil {
		s.debug.Println("Error encoding new cookie: " + err.Error())
		return "", err
	}
	return token, nil
}
