package gold

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
	"testing"
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
	assert.NoError(t, err)
	assert.Equal(t, resp2.StatusCode, 201)

	req1, err = http.NewRequest("GET", user1, nil)
	assert.NoError(t, err)
	resp1, err = user1h.Do(req1)
	assert.NoError(t, err)
	assert.Equal(t, user1, resp1.Header.Get("User"))

	req2, err = http.NewRequest("GET", user2, nil)
	assert.NoError(t, err)
	resp2, err = user2h.Do(req2)
	assert.NoError(t, err)
	assert.Equal(t, user2, resp2.Header.Get("User"))
}

func TestACLBlank(t *testing.T) {
	request, err := http.NewRequest("MKCOL", testServer.URL+"/_test/acldir/", nil)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	assert.NotNil(t, acl)

	request, err = http.NewRequest("PUT", acl, strings.NewReader(""))
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/acldir/abc", strings.NewReader("<a> <b> <c> ."))
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	acl = ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	assert.NotNil(t, acl)

	request, err = http.NewRequest("PUT", acl, strings.NewReader(""))
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/acldir/", nil)
	request.Header.Add("Accept", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLReadable(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/_test/acldir/", nil)
	request.Header.Add("Accept", "text/turtle")
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLCleanUp(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/_test/acldir/abc", nil)
	request.Header.Add("Accept", "text/turtle")
	response, err := user1h.Do(request)
	assert.Equal(t, 200, response.StatusCode)
	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	request, err = http.NewRequest("DELETE", acl, nil)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/acldir/", nil)
	request.Header.Add("Accept", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	acl = ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	request, err = http.NewRequest("DELETE", acl, nil)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/acldir/abc", nil)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/acldir/", nil)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

// func TestACLSetPolicies(t *testing.T) {
// 	testflight.WithServer(handler, func(r *testflight.Requester) {
// 		agentRead := "<http://www.w3.org/ns/auth/acl#accessTo> " +
// 			"   <http://presbrey.data.fm>, <>, </Public>, <https://presbrey.data.fm>;" +
// 			"<http://www.w3.org/ns/auth/acl#agentClass>" +
// 			"   <http://xmlns.com/foaf/0.1/Agent>;" +
// 			"<http://www.w3.org/ns/auth/acl#mode>" +
// 			"   <http://www.w3.org/ns/auth/acl#Read> ."

// 		response := r.Post("/_test/aclres", "text/turtle")

// 	})
// }

func TestACLCleanUsers(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Delete("/_test/user1", "", "")
		assert.Equal(t, 200, response.StatusCode)
		response = r.Delete("/_test/user2", "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
}
