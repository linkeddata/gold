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

func TestAddProfileKeys(t *testing.T) {
	webid := testServer.URL + "/_test/user1#id"
	var account = webidAccount{
		WebID: webid,
	}
	g := NewWebIDProfile(account)
	g, k, p, err := AddProfileKeys(webid, g)
	assert.NoError(t, err)
	assert.NotNil(t, k)
	assert.NotNil(t, p)
	assert.Equal(t, 15, g.Len())
}
