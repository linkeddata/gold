package gold

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DigestAuthentication structure
type DigestAuthentication struct {
	Type, Source, Username, Realm, Nonce, URI, QOP, NC, CNonce, Response, Opaque, Algorithm string
}

// DigestAuthorization structure
type DigestAuthorization struct {
	Type, Source, Username, Nonce, Signature string
}

func (req *httpRequest) authn(w http.ResponseWriter) string {
	user, err := req.userCookie()
	if err != nil {
		req.Server.debug.Println("userCookie error:", err)
	}
	if len(user) > 0 {
		req.Server.debug.Println("Cookie auth OK for User: " + user)
		return user
	}

	// try WebID-RSA
	if len(req.Header.Get("Authorization")) > 0 {
		user, err = WebIDDigestAuth(req)
		if err != nil {
			req.Server.debug.Println("WebID-RSA auth error:", err)
		}
		if len(user) > 0 {
			req.Server.debug.Println("WebID-RSA auth OK for User: " + user)
		}
	}
	// fall back to WebID-TLS
	if len(user) == 0 {
		user, err = WebIDTLSAuth(req)
		if err != nil {
			req.Server.debug.Println("WebID-TLS error:", err)
		}
		if len(user) > 0 {
			req.Server.debug.Println("WebID-TLS auth OK for User: " + user)
		}
	}

	if len(user) > 0 {
		if len(req.Header.Get("On-Behalf-Of")) > 0 {
			delegator := debrack(req.Header.Get("On-Behalf-Of"))
			if verifyDelegator(delegator, user) {
				req.Server.debug.Println("Setting delegation user to:", delegator)
				user = delegator
			}
		}
		req.Server.userCookieSet(w, user)
		return user
	}

	user = ""
	req.Server.debug.Println("Unauthenticated User")
	return user
}

func (req *httpRequest) userCookie() (string, error) {
	value := make(map[string]string)
	cookie, err := req.Cookie("Session")
	if err != nil {
		return "", errors.New(err.Error() + " Got: " + fmt.Sprintf("%s", req.Cookies()))
	}
	err = req.Server.cookie.Decode("Session", cookie.Value, &value)
	if err != nil {
		return "", err
	}
	return value["user"], nil
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
	cookieCfg := &http.Cookie{
		Expires: time.Now().Add(t),
		Name:    "Session",
		Path:    "/",
		Value:   encoded,
		Secure:  true,
	}
	http.SetCookie(w, cookieCfg)
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

// ParseDigestAuthenticateHeader parses an Authenticate header and returns a DigestAuthentication object
func ParseDigestAuthenticateHeader(header string) (*DigestAuthentication, error) {
	auth := DigestAuthentication{}

	if len(header) == 0 {
		return &auth, errors.New("Cannot parse WWW-Authenticate header: no header present")
	}

	opts := make(map[string]string)
	parts := strings.SplitN(header, " ", 2)
	opts["type"] = parts[0]
	parts = strings.Split(parts[1], ",")

	for _, part := range parts {
		vals := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := vals[0]
		val := strings.Replace(vals[1], "\"", "", -1)
		opts[key] = val
	}

	auth = DigestAuthentication{
		opts["type"],
		opts["source"],
		opts["username"],
		opts["realm"],
		opts["nonce"],
		opts["uri"],
		opts["qop"],
		opts["nc"],
		opts["qnonce"],
		opts["response"],
		opts["opaque"],
		opts["algorithm"],
	}
	return &auth, nil
}

// ParseDigestAuthorizationHeader parses an Authorization header and returns a DigestAuthorization object
func ParseDigestAuthorizationHeader(header string) (*DigestAuthorization, error) {
	auth := DigestAuthorization{}

	if len(header) == 0 {
		return &auth, errors.New("Cannot parse Authorization header: no header present")
	}

	opts := make(map[string]string)
	parts := strings.SplitN(header, " ", 2)
	opts["type"] = parts[0]
	if opts["type"] == "Bearer" {
		return &auth, errors.New("Not a Digest authorization header. Got " + opts["type"])
	}

	parts = strings.Split(parts[1], ",")

	for _, part := range parts {
		vals := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := vals[0]
		val := strings.Replace(vals[1], "\"", "", -1)
		opts[key] = val
	}

	auth = DigestAuthorization{
		opts["type"],
		opts["source"],
		opts["username"],
		opts["nonce"],
		opts["sig"],
	}
	return &auth, nil
}

func ParseBearerAuthorizationHeader(header string) (string, error) {
	if len(header) == 0 {
		return "", errors.New("Cannot parse Authorization header: no header present")
	}

	parts := strings.SplitN(header, " ", 2)
	if parts[0] != "Bearer" {
		return "", errors.New("Not a Bearer header. Got: " + parts[0])
	}
	return decodeQuery(parts[1])
}

func NewTokenValues() map[string]string {
	return make(map[string]string)
}

// NewSecureToken generates a signed token to be used during account recovery
func NewSecureToken(tokenType string, values map[string]string, duration time.Duration, s *Server) (string, error) {
	valid := time.Now().Add(duration).Unix()
	values["valid"] = fmt.Sprintf("%d", valid)
	token, err := s.cookie.Encode(tokenType, values)
	if err != nil {
		s.debug.Println("Error encoding new token: " + err.Error())
		return "", err
	}
	return token, nil
}

// ValidateSecureToken returns the values of a secure cookie
func ValidateSecureToken(tokenType string, token string, s *Server) (map[string]string, error) {
	values := make(map[string]string)
	err := s.cookie.Decode(tokenType, token, &values)
	if err != nil {
		s.debug.Println("Secure token decoding error: " + err.Error())
		return values, err
	}

	return values, nil
}

func GetValuesFromToken(tokenType string, token string, req *httpRequest, s *Server) (map[string]string, error) {
	values := NewTokenValues()
	token, err := decodeQuery(token)
	if err != nil {
		s.debug.Println("Token URL decoding error for type: " + tokenType + " : " + err.Error())
		return values, err
	}
	err = s.cookie.Decode(tokenType, token, &values)
	if err != nil {
		s.debug.Println("Token decoding error for type: " + tokenType + " \nToken: " + token + "\n" + err.Error())
		return values, err
	}
	return values, nil
}

func IsTokenDateValid(valid string) error {
	v, err := strconv.ParseInt(valid, 10, 64)
	if err != nil {
		return err
	}

	if time.Now().Local().Unix() > v {
		return errors.New("Token has expired!")
	}

	return nil
}

func GetAuthzFromToken(token string, req *httpRequest) (string, error) {
	// values, err := GetValuesFromToken("Authorization", token, req, s)
	values, err := req.Server.getPersistedToken("Authorization", req.Host, token)
	if err != nil {
		return "", err
	}
	if len(values["webid"]) == 0 && len(values["valid"]) == 0 &&
		len(values["origin"]) == 0 {
		return "", errors.New("Malformed token is missing required values")
	}
	err = IsTokenDateValid(values["valid"])
	if err != nil {
		return "", err
	}
	origin := req.Header.Get("Origin")
	if len(origin) > 0 && origin != values["origin"] {
		return "", errors.New("Cannot authorize user: " + req.User + ". Origin: " + origin + " does not match the origin in the token: " + values["origin"])
	}
	return values["webid"], nil
}

func saltedPassword(salt, pass string) string {
	s := sha256.Sum256([]byte(salt + pass))
	toString := fmt.Sprintf("%x", s)
	return toString
}

func encodeQuery(s string) string {
	return url.QueryEscape(s)
}

func decodeQuery(s string) (string, error) {
	return url.QueryUnescape(s)
}
