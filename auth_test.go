package gold

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestWebIDDigestAuth(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 401, response.StatusCode)
	wwwAuth := response.Header.Get("WWW-Authenticate")
	assert.NotEmpty(t, wwwAuth)

	//@@@TODO extract nonce
	authParsed, _ := ParseDigestAuthHeader(wwwAuth)

	// Load private key
	pKey := x509.MarshalPKCS1PrivateKey(user1k)
	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pKey,
	})
	signer, err := ParsePrivateKey(keyBytes)
	assert.NoError(t, err)

	toSign := user1 + authParsed.Nonce

	signed, err := signer.Sign([]byte(toSign))
	assert.NoError(t, err)

	sig := base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, sig)

	authHeader := `WebID-RSA username="` + user1 + `",
                     nonce="` + authParsed.Nonce + `",
                     sig="` + sig + `"`

	request, err = http.NewRequest("GET", testServer.URL+aclDir+"abc", nil)
	request.Header.Add("Authorization", authHeader)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
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
