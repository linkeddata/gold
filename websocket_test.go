package gold

import (
	"crypto/tls"
	"net"
	"net/http/httptest"
	"net/url"
	"testing"

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
	configWs.Root += "_test/"
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

func TestWebSocketSub(t *testing.T) {
	// sub URI
}

func TestWebSocketPub(t *testing.T) {
	// put URI

}
