package gold

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCORSRequestHasOrigin(t *testing.T) {
	requestOrigin := "https://example.com"
	url := testServer.URL + "/_test/user1"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	req.Header.Set("Origin", requestOrigin)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, requestOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestCORSRequestHasNoOrigin(t *testing.T) {
	url := testServer.URL + "/_test/user1"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestVaryHeader(t *testing.T) {
	url := testServer.URL + "/_test/user1"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, "Origin", resp.Header.Get("Vary"))
}
