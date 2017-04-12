package gold

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxyNoAuth(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/"+ProxyPath+"?uri="+testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Origin", "example.org")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Contains(t, response.Header.Get("Content-Type"), "text/turtle")
	assert.Equal(t, "example.org", response.Header.Get("Access-Control-Allow-Origin"))
	body, err := ioutil.ReadAll(response.Body)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Contains(t, string(body), "<http://www.w3.org/ns/ldp#BasicContainer>")
}

func TestProxyQueryOPTION(t *testing.T) {
	request, err := http.NewRequest("OPTIONS", testServer.URL+"/"+QueryPath, nil)
	assert.NoError(t, err)
	request.Header.Add("Origin", "example.org")
	request.Header.Add("Content-Type", "test/tql")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "example.org", response.Header.Get("Access-Control-Allow-Origin"))
	assert.True(t, strings.Contains(response.Header.Get("Access-Control-Expose-Headers"), "Content-Type"))
}
