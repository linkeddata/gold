package gold

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	config1, config2   *ServerConfig
	handler1, handler2 *Server
)

func init() {
	smtpCfg := EmailConfig{
		Name:     "Full Name",
		Addr:     "email@example.org",
		User:     "username",
		Pass:     "password",
		Host:     "localhost",
		Port:     3000,
		ForceSSL: false,
	}

	config1 = NewServerConfig()
	config1.DataRoot += "_test/"
	config1.Insecure = false
	config1.Vhosts = true
	config1.TokenAge = 5
	config1.Salt = "testsalt1"
	config1.SMTPConfig = smtpCfg
	handler1 = NewServer(config1)

	config2 = NewServerConfig()
	config2.DataRoot += "_test/"
	config2.Vhosts = false
	config2.Salt = "testsalt2"
	config2.SMTPConfig = smtpCfg
	handler2 = NewServer(config2)
}

func TestNewAccountWithoutVhosts(t *testing.T) {
	ts := httptest.NewUnstartedServer(handler2)
	ts.TLS = new(tls.Config)
	ts.TLS.ClientAuth = tls.RequestClientCert
	ts.TLS.NextProtos = []string{"http/1.1"}
	ts.StartTLS()

	form := url.Values{
		"username": {"user"},
		"password": {"zomg"},
		"email":    {"test@user.org"},
	}
	request, err := http.NewRequest("POST", ts.URL+"/"+SystemPrefix+"/new", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Empty(t, body)
	assert.Equal(t, 200, response.StatusCode)

	// request, err = http.NewRequest("HEAD", ts.URL+"/Preferences/prefs.ttl", nil)
	// assert.NoError(t, err)
	// response, err = httpClient.Do(request)
	// assert.NoError(t, err)
	// assert.Equal(t, 200, response.StatusCode)

	// request, err = http.NewRequest("HEAD", ts.URL+"/Preferences/typeIndex.ttl", nil)
	// assert.NoError(t, err)
	// response, err = httpClient.Do(request)
	// assert.NoError(t, err)
	// assert.Equal(t, 200, response.StatusCode)

	// request, err = http.NewRequest("HEAD", ts.URL+"/user/"+config1.ACLSuffix, nil)
	// assert.NoError(t, err)
	// response, err = httpClient.Do(request)
	// assert.NoError(t, err)
	// assert.Equal(t, 401, response.StatusCode)

	// form = url.Values{
	// 	"webid":    {user},
	// 	"password": {"zomg"},
	// }
	// request, err = http.NewRequest("POST", ts.URL+"/user/"+SystemPrefix+"/login", bytes.NewBufferString(form.Encode()))
	// assert.NoError(t, err)
	// request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	// response, err = httpClient.Do(request)
	// assert.NoError(t, err)
	// assert.Equal(t, 200, response.StatusCode)
	// cookie := response.Header.Get("Set-Cookie")
	// assert.NotNil(t, cookie)

	// request, err = http.NewRequest("HEAD", ts.URL+"/user/"+config1.ACLSuffix, nil)
	// assert.NoError(t, err)
	// request.Header.Add("Cookie", cookie)
	// response, err = httpClient.Do(request)
	// assert.NoError(t, err)
	// assert.Equal(t, 401, response.StatusCode)

	// delete user
	err = os.RemoveAll("_test/")
	assert.NoError(t, err)
}

func TestNewAccountWithVhosts(t *testing.T) {
	ts := httptest.NewUnstartedServer(handler1)
	ts.TLS = new(tls.Config)
	ts.TLS.ClientAuth = tls.RequestClientCert
	ts.TLS.NextProtos = []string{"http/1.1"}
	ts.StartTLS()

	form := url.Values{
		"username": {"user"},
		"password": {"zomg"},
		"email":    {"user@example.org"},
	}
	request, err := http.NewRequest("POST", ts.URL+"/"+SystemPrefix+"/new", bytes.NewBufferString(form.Encode()))
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

// func TestNewCertWithSPKAC(t *testing.T) {
// 	testServer1 := httptest.NewUnstartedServer(handler1)
// 	testServer1.TLS = new(tls.Config)
// 	testServer1.TLS.ClientAuth = tls.RequestClientCert
// 	testServer1.TLS.NextProtos = []string{"http/1.1"}
// 	testServer1.StartTLS()

// 	spkac := `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`
// 	form := url.Values{
// 		"spkac": {spkac},
// 		"webid": {"https://user.example.org/user/card#me"},
// 		"name":  {"Test User"},
// 	}
// 	request, err := http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/newCert", bytes.NewBufferString(form.Encode()))
// 	assert.NoError(t, err)
// 	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
// 	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
// 	request.Header.Add("User-Agent", "Chrome")
// 	response, err := httpClient.Do(request)
// 	assert.NoError(t, err)
// 	body, _ := ioutil.ReadAll(response.Body)
// 	response.Body.Close()
// 	assert.False(t, strings.Contains(string(body), "iframe"))
// 	assert.Equal(t, 200, response.StatusCode)

// 	webid, err := WebIDFromCert(body)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "https://user.example.org/user/card#me", webid)

// 	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/newCert", bytes.NewBufferString(form.Encode()))
// 	assert.NoError(t, err)
// 	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
// 	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
// 	request.Header.Add("User-Agent", "Firefox")
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	body, _ = ioutil.ReadAll(response.Body)
// 	response.Body.Close()
// 	assert.True(t, strings.Contains(string(body), "iframe"))
// 	assert.Equal(t, 200, response.StatusCode)

// 	certBase64 := strings.SplitAfter(string(body), "base64,")[1] //@@TODO indexOf
// 	certBase64 = strings.TrimRight(certBase64, "\"></iframe>")

// 	cert, err := base64.StdEncoding.DecodeString(certBase64)
// 	webid, err = WebIDFromCert(cert)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "https://user.example.org/user/card#me", webid)
// }

// func TestNewAccountWithSPKAC(t *testing.T) {
// 	testServer1 := httptest.NewUnstartedServer(handler1)
// 	testServer1.TLS = new(tls.Config)
// 	testServer1.TLS.ClientAuth = tls.RequestClientCert
// 	testServer1.TLS.NextProtos = []string{"http/1.1"}
// 	testServer1.StartTLS()

// 	spkac := `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`
// 	form := url.Values{"spkac": {spkac},
// 		"username": {"user"},
// 		"email":    {"test@user.org"},
// 	}
// 	request, err := http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/newAccount", bytes.NewBufferString(form.Encode()))
// 	assert.NoError(t, err)
// 	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
// 	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
// 	request.Header.Add("User-Agent", "Chrome")
// 	response, err := httpClient.Do(request)
// 	assert.NoError(t, err)
// 	body, _ := ioutil.ReadAll(response.Body)
// 	response.Body.Close()
// 	assert.False(t, strings.Contains(string(body), "iframe"))
// 	assert.Equal(t, 200, response.StatusCode)
// 	assert.Equal(t, "https://user."+strings.TrimLeft(testServer1.URL, "https://")+"/profile/card#me", response.Header.Get("User"))
// 	assert.NotEmpty(t, response.Cookies())

// 	webid, err := WebIDFromCert(body)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "https://user."+strings.TrimLeft(testServer1.URL, "https://")+"/profile/card#me", webid)

// 	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/newAccount", bytes.NewBufferString(form.Encode()))
// 	assert.NoError(t, err)
// 	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
// 	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.Equal(t, 406, response.StatusCode)

// 	// delete user
// 	err = os.RemoveAll("_test/user." + strings.TrimLeft(testServer1.URL, "https://"))
// 	assert.NoError(t, err)

// 	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/newAccount", bytes.NewBufferString(form.Encode()))
// 	assert.NoError(t, err)
// 	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
// 	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
// 	request.Header.Add("User-Agent", "Firefox")
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	body, _ = ioutil.ReadAll(response.Body)
// 	response.Body.Close()
// 	assert.True(t, strings.Contains(string(body), "iframe"))
// 	assert.Equal(t, 200, response.StatusCode)
// 	assert.Equal(t, "https://user."+strings.TrimLeft(testServer1.URL, "https://")+"/profile/card#me", response.Header.Get("User"))
// 	assert.NotEmpty(t, response.Cookies())

// 	certBase64 := strings.SplitAfter(string(body), "base64,")[1] //@@TODO indexOf
// 	certBase64 = strings.TrimRight(certBase64, "\"></iframe>")

// 	cert, err := base64.StdEncoding.DecodeString(certBase64)
// 	webid, err = WebIDFromCert(cert)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "https://user."+strings.TrimLeft(testServer1.URL, "https://")+"/profile/card#me", webid)

// 	err = os.RemoveAll("_test/")
// 	assert.NoError(t, err)
// }

func TestNewAccountWithoutSPKAC(t *testing.T) {
	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	form := url.Values{
		"username": {"user"},
		"password": {"zomg"},
		"email":    {"test@user.org"},
	}
	request, err := http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/new", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.False(t, strings.Contains(string(body), "iframe"))
	assert.Equal(t, 200, response.StatusCode)
	assert.NotEqual(t, "application/x-x509-user-cert; charset=utf-8", response.Header.Get("Content-Type"))
	assert.Equal(t, "https://user."+strings.TrimLeft(testServer1.URL, "https://")+"/profile/card#me", response.Header.Get("User"))
	assert.NotEmpty(t, response.Cookies())

	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/new", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 406, response.StatusCode)

	// delete user
	err = os.RemoveAll("_test/user." + strings.TrimLeft(testServer1.URL, "https://"))
	assert.NoError(t, err)

	err = os.RemoveAll("_test/")
	assert.NoError(t, err)
}

// func TestAccountInfo(t *testing.T) {
// 	err := handler2.StartBolt()
// 	assert.NoError(t, err)
// 	defer handler2.BoltDB.Close()

// 	testServer1 := httptest.NewUnstartedServer(handler2)
// 	testServer1.TLS = new(tls.Config)
// 	testServer1.TLS.ClientAuth = tls.RequestClientCert
// 	testServer1.TLS.NextProtos = []string{"http/1.1"}
// 	testServer1.StartTLS()

// 	request, err := http.NewRequest("GET", testServer1.URL+"/"+SystemPrefix+"/info", nil)
// 	assert.NoError(t, err)
// 	response, err := httpClient.Do(request)
// 	assert.NoError(t, err)
// 	body, _ := ioutil.ReadAll(response.Body)
// 	response.Body.Close()
// 	assert.Equal(t, 200, response.StatusCode)
// 	assert.NotEmpty(t, body)
// }

func TestAccountRecoveryForm(t *testing.T) {
	request, err := http.NewRequest("POST", testServer.URL+"/"+SystemPrefix+"/recovery", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Contains(t, string(body), "What is your WebID?")
}

func TestAccountRecovery(t *testing.T) {
	webid := "https://user.example.org/card#me"
	form := url.Values{
		"webid": {webid},
	}
	request, err := http.NewRequest("POST", testServer.URL+"/"+SystemPrefix+"/recovery", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 403, response.StatusCode)
	assert.Empty(t, response.Cookies())

	err = handler1.StartBolt()
	assert.NoError(t, err)
	defer handler1.BoltDB.Close()

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
		"email":    {"test@localhost"},
		"img":      {"https://img.org/"},
	}
	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/new", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Header.Add("User-Agent", "Chrome")
	request.Host = "localhost"
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	// FINISHED CREATING ACCOUNT

	// recover new account
	webid = "https://user/profile/card#me"
	form = url.Values{
		"webid": {webid},
	}
	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/recovery", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Host = "user.localhost"

	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Empty(t, response.Cookies())

	values := map[string]string{
		"webid": webid,
	}
	// set validity for now + 5 mins
	validity := time.Duration(config1.TokenAge) * time.Minute
	token, err := NewSecureToken("Recovery", values, validity, handler1)
	form = url.Values{
		"token": {token},
	}
	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/recovery", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.NotEmpty(t, response.Cookies())
	assert.Equal(t, "Session", response.Cookies()[0].Name)

	cookie := response.Header.Get("Set-Cookie")
	assert.NotNil(t, cookie)

	// Server info without credentials
	request, err = http.NewRequest("GET", testServer1.URL+"/"+SystemPrefix+"/tokens", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 401, response.StatusCode)

	// Server info without credentials
	request, err = http.NewRequest("GET", testServer1.URL+"/"+SystemPrefix+"/tokens", nil)
	assert.NoError(t, err)
	request.Header.Add("Cookie", cookie)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	// delete user
	err = os.RemoveAll("_test/")
	assert.NoError(t, err)
}

func TestAccountRecoverySecureSMTP(t *testing.T) {
	sc := NewServerConfig()
	sc.DataRoot += "_test/"
	sc.Vhosts = true
	sc.Insecure = true
	sc.SMTPConfig = EmailConfig{
		Name:     "Full Name",
		Addr:     "email@example.org",
		User:     "username",
		Pass:     "password",
		Host:     "localhost",
		Port:     3030,
		ForceSSL: true,
	}
	h := NewServer(sc)
	testServer1 := httptest.NewUnstartedServer(h)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	// create new account
	spkac := `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`
	form := url.Values{"spkac": {spkac},
		"username": {"user"},
		"name":     {"Test User"},
		"email":    {"test@localhost"},
		"img":      {"https://img.org/"},
	}
	request, err := http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/new", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Header.Add("User-Agent", "Chrome")
	request.Host = "localhost"
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	// FINISHED CREATING ACCOUNT

	// recover new account
	webid := "https://user/profile/card#me"
	form = url.Values{
		"webid": {webid},
	}
	// @@@TODO test
	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/recovery", bytes.NewBufferString(form.Encode()))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	request.Host = "user.localhost"

	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Empty(t, response.Cookies())

	values := map[string]string{
		"webid": webid,
	}
	// set validity for now + 5 mins
	validity := time.Duration(config1.TokenAge) * time.Minute
	token, err := NewSecureToken("Recovery", values, validity, h)
	form = url.Values{
		"token": {token},
	}
	request, err = http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/recovery", bytes.NewBufferString(form.Encode()))
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
		Method:      "status",
		AccountName: "user",
	}
	jsonData, err := json.Marshal(ar)
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/status", bytes.NewReader(jsonData))
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, `{"method":"status","status":"success","formURL":"`+testServer1.URL+`/`+SystemPrefix+`/new","loginURL":"`+testServer1.URL+`/user/`+SystemPrefix+`/login","logoutURL":"`+testServer1.URL+`/user/`+SystemPrefix+`/logout","response":{"accountURL":"`+testServer1.URL+`/user/","available":true}}`, string(body))
	assert.Equal(t, 200, response.StatusCode)

	// delete user
	err = os.RemoveAll("_test/")
	assert.NoError(t, err)
}

func TestAccountStatusWithVhosts(t *testing.T) {
	// test vhosts
	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	ar := accountRequest{
		Method:      "status",
		AccountName: "user",
	}
	jsonData, err := json.Marshal(ar)
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", testServer1.URL+"/"+SystemPrefix+"/status", bytes.NewReader(jsonData))
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, `{"method":"status","status":"success","formURL":"`+testServer1.URL+`/`+SystemPrefix+`/new","loginURL":"https://user.`+strings.TrimLeft(testServer1.URL, "https://")+`/`+SystemPrefix+`/login","logoutURL":"https://user.`+strings.TrimLeft(testServer1.URL, "https://")+`/`+SystemPrefix+`/logout","response":{"accountURL":"https://user.`+strings.TrimLeft(testServer1.URL, "https://")+`/","available":true}}`, string(body))
	assert.Equal(t, 200, response.StatusCode)
}
