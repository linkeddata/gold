package gold

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxy(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/"+ProxyPath+"?uri="+testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Origin", "https://example.org/")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Contains(t, response.Header.Get("Content-Type"), "text/turtle")
	body, err := ioutil.ReadAll(response.Body)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Contains(t, string(body), "<http://www.w3.org/ns/ldp#BasicContainer>")
}
