package gold

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/websocket"
)

var (
	wsOrigin, wsURI string
	testServerWs    *httptest.Server
	wsCfg1          *websocket.Config
)

func init() {
	wsOrigin = "http://localhost/"

	configWs := NewServerConfig()
	configWs.DataRoot += "_test/"
	configWs.Vhosts = false
	handlerWs := NewServer(configWs)

	testServerWs = httptest.NewUnstartedServer(handlerWs)
	testServerWs.TLS = new(tls.Config)
	testServerWs.TLS.InsecureSkipVerify = true
	testServerWs.TLS.ClientAuth = tls.RequestClientCert
	testServerWs.TLS.NextProtos = []string{"http/1.1"}
	testServerWs.StartTLS()

	p, _ := url.Parse(testServerWs.URL)
	host, port, _ := net.SplitHostPort(p.Host)

	wsURI = "wss://" + host + ":" + port
	wsCfg1, _ = websocket.NewConfig(wsURI, wsOrigin)
}

func TestWebSocketPing(t *testing.T) {
	config := tls.Config{
		Certificates:       []tls.Certificate{*user1cert},
		InsecureSkipVerify: true,
	}
	wsCfg1.TlsConfig = &config
	ws, err := websocket.DialConfig(wsCfg1)
	assert.NoError(t, err)
	_, err = ws.Write([]byte("ping"))
	assert.NoError(t, err)

	msg := make([]byte, 512)
	var n int
	n, err = ws.Read(msg)
	assert.NoError(t, err)
	assert.Equal(t, "pong", string(msg[:n]))
}

func TestWebSocketSubPub(t *testing.T) {
	resURL := testServerWs.URL + "/abc"

	config := tls.Config{
		Certificates:       []tls.Certificate{*user1cert},
		InsecureSkipVerify: true,
	}
	wsCfg1.TlsConfig = &config
	ws, err := websocket.DialConfig(wsCfg1)
	assert.NoError(t, err)
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))

	_, err = ws.Write([]byte("sub " + testServerWs.URL + "/"))
	assert.NoError(t, err)

	msg := make([]byte, 512)
	var n int
	n, err = ws.Read(msg)
	assert.NoError(t, err)
	assert.Equal(t, "ack", string(msg[:3]))
	assert.Equal(t, testServerWs.URL+"/", string(msg[4:n]))

	_, err = ws.Write([]byte("sub " + resURL))
	assert.NoError(t, err)

	msg = make([]byte, 512)
	n, err = ws.Read(msg)
	assert.NoError(t, err)
	assert.Equal(t, "ack", string(msg[:3]))
	assert.Equal(t, resURL, string(msg[4:n]))

	request, err := http.NewRequest("PUT", resURL, strings.NewReader("<a> <b> <c>."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	msg = make([]byte, 512)
	n, err = ws.Read(msg)
	assert.NoError(t, err)
	assert.Equal(t, "pub "+resURL, string(msg[:n]))

	request, err = http.NewRequest("POST", testServerWs.URL+"/", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
	request.Header.Add("Slug", "dir")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	msg = make([]byte, 512)
	n, err = ws.Read(msg)
	assert.NoError(t, err)
	assert.Equal(t, "pub "+testServerWs.URL+"/", string(msg[:n]))

	request, err = http.NewRequest("DELETE", testServerWs.URL+"/dir/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(response.Body)
	assert.NoError(t, err)
	response.Body.Close()
	println(string(body))
	assert.Equal(t, 200, response.StatusCode)

	msg = make([]byte, 512)
	n, err = ws.Read(msg)
	assert.NoError(t, err)
	assert.Equal(t, "pub "+testServerWs.URL+"/", string(msg[:n]))

	request, err = http.NewRequest("POST", testServerWs.URL+"/", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("Slug", "res")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	msg = make([]byte, 512)
	n, err = ws.Read(msg)
	assert.NoError(t, err)
	assert.Equal(t, "pub "+testServerWs.URL+"/", string(msg[:n]))

	_, err = ws.Write([]byte("unsub " + resURL))
	assert.NoError(t, err)

	msg = make([]byte, 512)
	n, err = ws.Read(msg)
	assert.NoError(t, err)
	assert.Equal(t, "removed "+resURL, string(msg[:n]))

	err = os.RemoveAll("_test/")
	assert.NoError(t, err)
}
