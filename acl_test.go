package gold

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"

	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
)

const (
	aclDir = "/_test/acldir/"
)

var (
	user1, user2   string
	user1g, user2g *Graph
	user1k, user2k *rsa.PrivateKey
	user1h, user2h *http.Client
)

func TestACLInit(t *testing.T) {
	var err error

	user1 = testServer.URL + "/_test/user1#id"
	user1g, user1k, err = newRSA(user1)
	user1cert, err := newRSAcert(user1, user1k)
	assert.NoError(t, err)
	user1h = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*user1cert},
				InsecureSkipVerify: true,
				Rand:               rand.Reader,
			},
		},
	}
	user1n3, err := user1g.Serialize("text/turtle")
	assert.NoError(t, err)
	req1, err := http.NewRequest("PUT", user1, strings.NewReader(user1n3))
	assert.NoError(t, err)
	resp1, err := httpClient.Do(req1)
	resp1.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, resp1.StatusCode, 201)

	user2 = testServer.URL + "/_test/user2#id"
	user2g, user2k, err = newRSA(user2)
	user2cert, err := newRSAcert(user2, user2k)
	assert.NoError(t, err)
	user2h = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*user2cert},
				InsecureSkipVerify: true,
				Rand:               rand.Reader,
			},
		},
	}
	user2n3, err := user2g.Serialize("text/turtle")
	assert.NoError(t, err)
	req2, err := http.NewRequest("PUT", user2, strings.NewReader(user2n3))
	assert.NoError(t, err)
	resp2, err := httpClient.Do(req2)
	resp2.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, resp2.StatusCode, 201)

	req1, err = http.NewRequest("GET", user1, nil)
	assert.NoError(t, err)
	resp1, err = user1h.Do(req1)
	resp1.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, user1, resp1.Header.Get("User"))

	req2, err = http.NewRequest("GET", user2, nil)
	assert.NoError(t, err)
	resp2, err = user2h.Do(req2)
	resp2.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, user2, resp2.Header.Get("User"))
}

func TestACLEmpty(t *testing.T) {
	request, err := http.NewRequest("MKCOL", testServer.URL+aclDir, nil)
	response, err := user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	assert.NotNil(t, acl)

	request, err = http.NewRequest("PUT", acl, strings.NewReader(""))
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+aclDir+"abc", strings.NewReader("<a> <b> <c> ."))
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	acl = ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	assert.NotNil(t, acl)

	request, err = http.NewRequest("PUT", acl, strings.NewReader(""))
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("GET", acl, nil)
	request.Header.Add("Accept", "text/turtle")
	response, err = user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLOwner(t *testing.T) {
	request, err := http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	response, err := user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + ">, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	acl = ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	// user1
	request, err = http.NewRequest("HEAD", acl, nil)
	request.Header.Add("Accept", "text/turtle")
	response, err = user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "5", response.Header.Get("Triples"))

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)
	// user2
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("HEAD", acl, nil)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("PUT", acl, strings.NewReader("<d> <e> <f> ."))
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 403, response.StatusCode)
	// agent
	request, err = http.NewRequest("PUT", acl, strings.NewReader("<d> <e> <f> ."))
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 403, response.StatusCode)

	//TODO: add test for defaultForNew
}

func TestACLFriendsOnly(t *testing.T) {

}

func TestACLPublic(t *testing.T) {

}

func TestACLAppendOnly(t *testing.T) {

}

func TestACLCleanUp(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+aclDir+"abc", nil)
	request.Header.Add("Accept", "text/turtle")
	response, err := user1h.Do(request)
	assert.Equal(t, 200, response.StatusCode)
	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	request, err = http.NewRequest("DELETE", acl, nil)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+aclDir, nil)
	request.Header.Add("Accept", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	acl = ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	request, err = http.NewRequest("DELETE", acl, nil)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+aclDir+"abc", nil)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+aclDir, nil)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLCleanUsers(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Delete("/_test/user1", "", "")
		assert.Equal(t, 200, response.StatusCode)
		response = r.Delete("/_test/user2", "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
}
