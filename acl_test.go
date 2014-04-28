package gold

import (
	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
	"net/http"
	"path/filepath"
	"testing"
)

func TestACLWriteTrue(t *testing.T) {
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

func TestACLReadTrue(t *testing.T) {
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
