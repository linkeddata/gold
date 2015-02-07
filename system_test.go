package gold

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAccount(t *testing.T) {
	spkac := `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`
	form := url.Values{"spkac": {spkac},
		"username": {"_test/user"},
		"name":     {"Test User"},
		"email":    {"test@user.org"},
		"img":      {"https://img.org/"},
	}
	request, err := http.NewRequest("POST", testServer.URL+"/,system/newAccount", bytes.NewBufferString(form.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Header.Add("User-Agent", "Chrome")
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.False(t, strings.Contains(string(body), "iframe"))
	assert.Equal(t, 200, response.StatusCode)

	webid, err := GetWebIDFromCert(body)
	assert.NoError(t, err)
	assert.Equal(t, testServer.URL+"/_test/user/profile/card#me", webid)

	request, err = http.NewRequest("POST", testServer.URL+"/,system/newAccount", bytes.NewBufferString(form.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 406, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/user/profile/card", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+"/,system/newAccount", bytes.NewBufferString(form.Encode()))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Header.Add("User-Agent", "Firefox")
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	body, _ = ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.True(t, strings.Contains(string(body), "iframe"))
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/user/profile/card", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/user/profile/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/user/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestAccountStatus(t *testing.T) {
	// test vhosts
	handler1 := NewServer(GetServerRoot()+"/_test/", true)
	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	ar := accountRequest{
		Method:      "accountStatus",
		AccountName: "deiu",
	}
	jsonData, err := json.Marshal(ar)
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", testServer1.URL+"/,system/accountStatus", bytes.NewReader(jsonData))
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, `{"method":"accountStatus","status":"success","formuri":"`+testServer1.URL+`/,system/newAccount","response":{"accountName":"deiu","available":true}}`, string(body))
	assert.Equal(t, 200, response.StatusCode)
}
