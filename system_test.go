package gold

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	config1, config2   *ServerConfig
	handler1, handler2 *Server
)

func init() {
	config1 = NewServerConfig()
	config1.DataRoot += "_test/"
	config1.Vhosts = true
	handler1 = NewServer(config1)

	config2 = NewServerConfig()
	config2.DataRoot += "_test/"
	config2.Vhosts = false
	handler2 = NewServer(config2)
}

func TestNewAccountWithoutVhosts(t *testing.T) {
	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	form := url.Values{
		"username": {"user"},
		"name":     {"Test User"},
		"email":    {"test@user.org"},
		"img":      {"https://img.org/"},
	}
	request, err := http.NewRequest("POST", testServer1.URL+"/,system/newAccount", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
	assert.Empty(t, body)

	// delete user
	err = os.RemoveAll("_test/")
	assert.NoError(t, err)
}

func TestNewAccountWithVhosts(t *testing.T) {
	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	form := url.Values{
		"username": {"user"},
		"email":    {"user@example.org"},
	}
	request, err := http.NewRequest("POST", testServer1.URL+"/,system/newAccount", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
	assert.Empty(t, body)

	// delete user
	err = os.RemoveAll("_test/")
	assert.NoError(t, err)
}

func TestNewCertWithSPKAC(t *testing.T) {
	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	spkac := `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`
	form := url.Values{
		"spkac": {spkac},
		"webid": {"https://user.example.org/user/card#me"},
		"name":  {"Test User"},
	}
	request, err := http.NewRequest("POST", testServer1.URL+"/,system/newCert", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Header.Add("User-Agent", "Chrome")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.False(t, strings.Contains(string(body), "iframe"))
	assert.Equal(t, 200, response.StatusCode)

	webid, err := WebIDFromCert(body)
	assert.NoError(t, err)
	assert.Equal(t, "https://user.example.org/user/card#me", webid)

	request, err = http.NewRequest("POST", testServer1.URL+"/,system/newCert", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Header.Add("User-Agent", "Firefox")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	body, _ = ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.True(t, strings.Contains(string(body), "iframe"))
	assert.Equal(t, 200, response.StatusCode)

	certBase64 := strings.SplitAfter(string(body), "base64,")[1] //@@TODO indexOf
	certBase64 = strings.TrimRight(certBase64, "\"></iframe>")

	cert, err := base64.StdEncoding.DecodeString(certBase64)
	webid, err = WebIDFromCert(cert)
	assert.NoError(t, err)
	assert.Equal(t, "https://user.example.org/user/card#me", webid)
}

func TestNewAccountWithSPKAC(t *testing.T) {
	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	spkac := `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`
	form := url.Values{"spkac": {spkac},
		"username": {"user"},
		"name":     {"Test User"},
		"email":    {"test@user.org"},
		"img":      {"https://img.org/"},
	}
	request, err := http.NewRequest("POST", testServer1.URL+"/,system/newAccount", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Header.Add("User-Agent", "Chrome")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.False(t, strings.Contains(string(body), "iframe"))
	assert.Equal(t, 200, response.StatusCode)

	webid, err := WebIDFromCert(body)
	assert.NoError(t, err)
	assert.Equal(t, "https://user."+strings.TrimLeft(testServer1.URL, "https://")+"/profile/card#me", webid)

	request, err = http.NewRequest("POST", testServer1.URL+"/,system/newAccount", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 406, response.StatusCode)

	// delete user
	err = os.RemoveAll("_test/user." + strings.TrimLeft(testServer1.URL, "https://"))
	assert.NoError(t, err)

	request, err = http.NewRequest("POST", testServer1.URL+"/,system/newAccount", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Header.Add("User-Agent", "Firefox")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	body, _ = ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.True(t, strings.Contains(string(body), "iframe"))
	assert.Equal(t, 200, response.StatusCode)

	certBase64 := strings.SplitAfter(string(body), "base64,")[1] //@@TODO indexOf
	certBase64 = strings.TrimRight(certBase64, "\"></iframe>")

	cert, err := base64.StdEncoding.DecodeString(certBase64)
	webid, err = WebIDFromCert(cert)
	assert.NoError(t, err)
	assert.Equal(t, "https://user."+strings.TrimLeft(testServer1.URL, "https://")+"/profile/card#me", webid)

	err = os.RemoveAll("_test/")
	assert.NoError(t, err)
}

func TestAccountRecovery(t *testing.T) {
	webid := "https://user.example.org/card#me"
	form := url.Values{
		"webid": {webid},
	}
	request, err := http.NewRequest("POST", testServer.URL+"/"+SystemPrefix+"/accountRecovery", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 403, response.StatusCode)
	assert.Empty(t, response.Cookies())

	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	// create new account
	spkac := `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`
	form = url.Values{"spkac": {spkac},
		"username": {"user"},
		"name":     {"Test User"},
		"email":    {"test@user.org"},
		"img":      {"https://img.org/"},
	}
	request, err = http.NewRequest("POST", testServer1.URL+"/,system/newAccount", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Header.Add("User-Agent", "Chrome")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	// recover new account
	webid = "https://user." + strings.TrimLeft(testServer1.URL, "https://") + "/profile/card#me"
	form = url.Values{
		"webid": {webid},
	}
	// @@@TODO test
	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/accountRecovery", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Host = "user"

	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Empty(t, response.Cookies())

	token, err := NewRecoveryToken(webid, handler1)
	form = url.Values{
		"token": {token},
	}
	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/accountRecovery", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.NotEmpty(t, response.Cookies())
	assert.Equal(t, "Session", response.Cookies()[0].Name)

	// delete user
	err = os.RemoveAll("_test/")
	assert.NoError(t, err)
}

func TestAccountStatusWithoutVhosts(t *testing.T) {
	// test vhosts
	testServer1 := httptest.NewUnstartedServer(handler2)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	ar := accountRequest{
		Method:      "accountStatus",
		AccountName: "user",
	}
	jsonData, err := json.Marshal(ar)
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", testServer1.URL+"/,system/accountStatus", bytes.NewReader(jsonData))
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, `{"method":"accountStatus","status":"success","formURL":"`+testServer1.URL+`/,system/newAccount","loginURL":"`+testServer1.URL+`/user/","response":{"accountURL":"`+testServer1.URL+`/user/","available":true}}`, string(body))
	assert.Equal(t, 200, response.StatusCode)
}

func TestAccountStatusWithVhosts(t *testing.T) {
	// test vhosts
	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	ar := accountRequest{
		Method:      "accountStatus",
		AccountName: "user",
	}
	jsonData, err := json.Marshal(ar)
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", testServer1.URL+"/,system/accountStatus", bytes.NewReader(jsonData))
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, `{"method":"accountStatus","status":"success","formURL":"`+testServer1.URL+`/,system/newAccount","loginURL":"https://user.`+strings.TrimLeft(testServer1.URL, "https://")+`/","response":{"accountURL":"https://user.`+strings.TrimLeft(testServer1.URL, "https://")+`/","available":true}}`, string(body))
	assert.Equal(t, 200, response.StatusCode)
}

func TestAccountInfo(t *testing.T) {
	err := os.MkdirAll("_test/user", 0755)
	assert.NoError(t, err)

	sizeLocal, err := DiskUsage("_test/")
	assert.NoError(t, err)

	testServer1 := httptest.NewUnstartedServer(handler2)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	request, err := http.NewRequest("GET", testServer1.URL+"/,system/accountInfo", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()

	err = os.RemoveAll("_test/")
	assert.NoError(t, err)

	assert.Equal(t, 200, response.StatusCode)
	assert.NotEmpty(t, body)

	dataLocal := accountInformation{
		DiskUsed:  fmt.Sprintf("%d", sizeLocal),
		DiskLimit: fmt.Sprintf("%d", config2.DiskLimit),
	}
	jsonData, err := json.Marshal(dataLocal)
	assert.Equal(t, body, jsonData)
}
