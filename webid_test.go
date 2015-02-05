package gold

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWebIDTLSauth(t *testing.T) {
	request, err := http.NewRequest("HEAD", testServer.URL, nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	assert.Equal(t, user1, response.Header.Get("User"))
}

func TestNewWebIDProfile(t *testing.T) {
	g, k, err := NewWebIDProfile(user1)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	assert.Equal(t, 4, g.Len())
}
