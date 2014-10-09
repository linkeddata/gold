package gold

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/gorilla/securecookie"
)

var (
	s = NewSecureCookie()
)

// Converts string to sha2
func SHA2(str string) string {
	bytes := []byte(str)

	h := sha256.New()
	h.Write(bytes)

	return hex.EncodeToString(h.Sum(nil))
}

func NewSecureCookie() *securecookie.SecureCookie {
	return securecookie.New(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
}

func SetCookieHandler(w http.ResponseWriter, user string) {
	DebugLog("Cookie", "Setting new cookie for "+user)
	value := map[string]string{
		"user": user,
	}
	if encoded, err := s.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	} else {
		DebugLog("Cookie", "Error encoding cookie: "+err.Error())
	}
}

func ReadCookieHandler(w http.ResponseWriter, r *httpRequest) (user string) {
	//DebugLog("Cookie", "Cookie: "+fmt.Sprintf("%+v\n", s))
	user = ""
	cookie, err := r.Cookie("session")
	if err == nil {
		value := make(map[string]string)
		if err = s.Decode("session", cookie.Value, &value); err == nil {
			user = value["user"]
			DebugLog("Cookie", "The value of User is "+user)
			return
		} else {
			DebugLog("Cookie", "Error decoding cookie: "+err.Error())
		}
	} else {
		DebugLog("Cookie", "Error reading cookie: "+err.Error())
	}

	return
}
