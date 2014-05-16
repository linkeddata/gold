package gold

import (
	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
	"net/http"
	"path/filepath"
	"testing"
)

func TestACLBlank(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("MKCOL", "/_test/acldir/", nil)
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		acl := ParseLinkHeader(response.RawResponse.Header.Get("Link")).MatchRel("acl")

		response = r.Put("/_test/acldir/abc", "text/turtle", "<a> <b> <c> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 201, response.StatusCode)

		acl = ParseLinkHeader(response.RawResponse.Header.Get("Link")).MatchRel("acl")

		request, _ = http.NewRequest("GET", "/_test/acldir/", nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestACLReadable(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/_test/acldir/", nil)
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

func TestACLBlank(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("MKCOL", "/_test/acldir/", nil)
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		response = r.Put("/_test/acldir/abc", "text/turtle", "<a> <b> <c> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 201, response.StatusCode)

		request, _ = http.NewRequest("GET", "/_test/acldir/", nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestACLCleanUp(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Delete("/_test/acldir/abc", "", "")
		assert.Equal(t, 200, response.StatusCode)

		response = r.Delete("/_test/acldir/", "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
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
