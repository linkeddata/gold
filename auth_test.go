package gold

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSecureToken(t *testing.T) {
	tokenValues := map[string]string{
		"secret": string(handler.cookieSalt),
	}
	validity := 1 * time.Minute
	token, err := NewSecureToken("WWW-Authenticate", tokenValues, validity, handler)
	assert.NoError(t, err)
	assert.Equal(t, 184, len(token))
}

func TestParseDigestAuthorizationHeader(t *testing.T) {
	h := "WebID-RSA source=\"http://server.org/\", webid=\"http://example.org/\", keyurl=\"http://example.org/keys/abc\", nonce=\"string1\", sig=\"string2\""
	p, err := ParseDigestAuthorizationHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "WebID-RSA", p.Type)
	assert.Equal(t, "http://server.org/", p.Source)
	assert.Equal(t, "http://example.org/", p.Webid)
	assert.Equal(t, "http://example.org/keys/abc", p.KeyURL)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "string2", p.Signature)
}

func TestParseDigestAuthenticateHeader(t *testing.T) {
	h := `WebID-RSA source="http://server.org/", nonce="string1"`

	p, err := ParseDigestAuthenticateHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "WebID-RSA", p.Type)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "http://server.org/", p.Source)
}

func TestCookieAuth(t *testing.T) {
	request, err := http.NewRequest("MKCOL", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+aclDir+"abc", strings.NewReader("<a> <b> <c> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	cookie1 := response.Header.Get("Set-Cookie")
	assert.NotNil(t, cookie1)
	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	assert.NotNil(t, acl)

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + "abc>, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ." +
		"<#Restricted>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + "abc>;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user2 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write>."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	request.Header.Add("Cookie", cookie1)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	cookie2 := response.Header.Get("Set-Cookie")
	assert.NotNil(t, cookie2)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	request.Header.Add("Cookie", cookie2)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 401, response.StatusCode)

}

func TestWebIDRSAAuth(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 401, response.StatusCode)
	wwwAuth := response.Header.Get("WWW-Authenticate")
	assert.NotEmpty(t, wwwAuth)

	p, _ := ParseDigestAuthenticateHeader(wwwAuth)

	// Load private key
	pKey := x509.MarshalPKCS1PrivateKey(user1k)
	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pKey,
	})
	signer, err := ParseRSAPrivatePEMKey(keyBytes)
	assert.NoError(t, err)

	// Load public key
	pubPEM := bytes.NewBuffer(nil)
	pubBytes, err := x509.MarshalPKIXPublicKey(user1p)
	assert.NoError(t, err)
	err = pem.Encode(pubPEM, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})
	assert.NoError(t, err)

	// Hash the key to use in the URL and store it on the server
	hash := fmt.Sprintf("%x", sha1.Sum([]byte(pubPEM.String())))
	keyURL := testServer.URL + "/_test/keys/" + hash

	claim := sha1.Sum([]byte(p.Source + user1 + keyURL + p.Nonce))
	signed, err := signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig := base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, b64Sig)

	authHeader := `WebID-RSA source="` + p.Source + `", webid="` + user1 + `", keyurl="` + keyURL + `", nonce="` + p.Nonce + `", sig="` + b64Sig + `"`

	request, err = http.NewRequest("GET", testServer.URL+aclDir+"abc", nil)
	request.Header.Add("Authorization", authHeader)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestWebIDRSAAuthBadSource(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 401, response.StatusCode)
	wwwAuth := response.Header.Get("WWW-Authenticate")
	assert.NotEmpty(t, wwwAuth)

	p, _ := ParseDigestAuthenticateHeader(wwwAuth)

	// Load private key
	pKey := x509.MarshalPKCS1PrivateKey(user1k)
	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pKey,
	})
	signer, err := ParseRSAPrivatePEMKey(keyBytes)
	assert.NoError(t, err)

	// Bad source
	claim := sha1.Sum([]byte("http://baddude.org/" + user1 + p.Nonce))
	signed, err := signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig := base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, b64Sig)

	authHeader := `WebID-RSA source="http://baddude.org/", username="` + user1 + `", nonce="` + p.Nonce + `", sig="` + b64Sig + `"`

	request, err = http.NewRequest("GET", testServer.URL+aclDir+"abc", nil)
	request.Header.Add("Authorization", authHeader)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 401, response.StatusCode)
}

func TestCleanupAuth(t *testing.T) {
	request, err := http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	request, err = http.NewRequest("DELETE", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLCleanUsers(t *testing.T) {
	request, err := http.NewRequest("DELETE", testServer.URL+"/_test/profile/user1", nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/profile/user2", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}
