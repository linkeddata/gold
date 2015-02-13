package gold

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

var (
	// CookieAge contains the default validity of the cookie
	CookieAge = 24 * time.Hour

	s = NewSecureCookie()
)

// NewSecureCookie creates a new cookie
func NewSecureCookie() *securecookie.SecureCookie {
	return securecookie.New(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
}

// SetCookie sets a cookie during the HTTP response
func SetCookie(w http.ResponseWriter, user string) error {
	value := map[string]string{
		"user": user,
	}
	encoded, err := s.Encode("Session", value)
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Expires: time.Now().Add(CookieAge),
		Name:    "Session",
		Path:    "/",
		Value:   encoded,
	}
	http.SetCookie(w, cookie)
	return nil
}

// ReadCookie reads a cookie from the request
func ReadCookie(w http.ResponseWriter, r *httpRequest) (user string) {
	user = ""
	cookie, err := r.Cookie("Session")
	if err == nil {
		value := make(map[string]string)
		if err = s.Decode("Session", cookie.Value, &value); err == nil {
			user = value["user"]
			r.Server.debug.Println("The value of User is " + user)
			return
		}
		r.Server.debug.Println("Error decoding cookie: " + err.Error())
	}
	r.Server.debug.Println("Error reading cookie: " + err.Error())

	return
}

// DeleteCookie deletes an existing cookie
func DeleteCookie(w http.ResponseWriter, user string) {
	cookie := &http.Cookie{
		Name:   "Session",
		Value:  "deleted",
		Path:   "/",
		MaxAge: -1,
	}

	http.SetCookie(w, cookie)
}
