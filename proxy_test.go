package gold

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxy(t *testing.T) {
	// This test has to use a local resource for offline testing
	request, err := http.NewRequest("GET", testServer.URL+"/"+ProxyPath+"?uri=http://www.w3.org/ns/auth/acl", nil)
	assert.NoError(t, err)
	request.Header.Add("Origin", "https://example.org/")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Contains(t, response.Header.Get("Content-Type"), "application/rdf+xml")
	body, err := ioutil.ReadAll(response.Body)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Contains(t, string(body), "<rdf:RDF")
}
