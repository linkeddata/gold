package gold

import (
	"net/http"
	"testing"

	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
)

func TestProxy(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", ProxyPath+"?uri=http://www.w3.org/ns/auth/acl", nil)
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Contains(t, response.RawResponse.Header.Get("Content-Type"), "application/rdf+xml")
		assert.Contains(t, response.Body, "<rdf:RDF")
	})
}
