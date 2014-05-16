package gold

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
)

var (
	user1, user2   string
	user1g, user2g *Graph
	user1k, user2k *rsa.PrivateKey
	user1h, user2h *http.Client
)

func TestACLInit(t *testing.T) {
	var err error

	user1 = testServer.URL + "/user1#id"
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

	user2 = testServer.URL + "/user2#id"
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
}

func TestACLWritable(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Post("/_test/aclres", "text/turtle", "<a> <b> <c> .")
		assert.Equal(t, 200, response.StatusCode)

		acl := ParseLinkHeader(response.RawResponse.Header.Get("Link")).MatchRel("acl")
		assert.Equal(t, "/_test/aclres,acl", acl)

		response = r.Put(acl, "text/turtle", "<d> <e> <f> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 201, response.StatusCode)
	})
}

func TestACLReadable(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/_test/aclres", nil)
		request.Header.Add("Accept", "text/turtle")
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)

		// Cleanup
		response = r.Delete("/_test/aclres", "", "")
		assert.Equal(t, 200, response.StatusCode)

		acl := ParseLinkHeader(response.RawResponse.Header.Get("Link")).MatchRel("acl")

		response = r.Delete(acl, "", "")
		assert.Equal(t, 200, response.StatusCode)

		response = r.Delete(filepath.Dir(acl), "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
}
