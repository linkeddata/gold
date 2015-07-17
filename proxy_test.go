package gold

import (
	"io/ioutil"
	"net/http"
	"testing"
	// -----
	// "crypto/x509"
	// "encoding/pem"
	// "io"
	// "os"
	// "strings"
	// -----
	// "crypto/tls"
	// "net/http/httptest"
	// "strings"

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
	println("User:", response.Header.Get("User"))
	assert.Contains(t, string(body), "<http://www.w3.org/ns/ldp#BasicContainer>")
}

func TestAuthProxy(t *testing.T) {
	request, err := http.NewRequest("POST", testServer.URL+"/"+DelegationProxy+"?uri="+testServer.URL, nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 405, response.StatusCode)

	// generate agent profile + keys
	// agent, _ := handler.pathInfo("https://localhost:4443/tests/agent#id")
	// agentg, agentk, _, err := NewWebIDProfileWithKeys(agent.URI)
	// assert.NoError(t, err)
	// // create cert
	// agentc, err := NewRSADerCert(agent.URI, "Agent", agentk)
	// assert.NoError(t, err)
	// // serialize
	// agentn3, err := agentg.Serialize("text/turtle")
	// assert.NoError(t, err)
	// // write profile
	// profile, err := os.Create(agent.File)
	// assert.NoError(t, err)
	// _, err = io.Copy(profile, strings.NewReader(agentn3))
	// assert.NoError(t, err)
	// profile.Close()

	// // write key
	// keyOut, err := os.Create(agent.File + ".key")
	// assert.NoError(t, err)
	// pem.Encode(keyOut, &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(agentk),
	// })
	// keyOut.Close()

	// // write cert
	// certOut, err := os.Create(agent.File + ".crt")
	// assert.NoError(t, err)
	// pem.Encode(certOut, &pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: agentc,
	// })
	// certOut.Close()

	// -------------------
	// agent, _ := handler.pathInfo(testServer.URL + "/tests/agent")
	// configAgent := NewServerConfig()
	// configAgent.Debug = true
	// configAgent.AgentKey = agent.File + ".key"
	// configAgent.AgentCert = agent.File + ".crt"
	// handlerAgent := NewServer(configAgent)
	// testServerAgent := httptest.NewUnstartedServer(handlerAgent)
	// testServerAgent.TLS = new(tls.Config)
	// testServerAgent.TLS.ClientAuth = tls.RequestClientCert
	// testServerAgent.TLS.NextProtos = []string{"http/1.1"}
	// testServerAgent.StartTLS()
	// testServerAgent.URL = strings.Replace(testServerAgent.URL, "127.0.0.1", "localhost", 1)

	// request, err := http.NewRequest("GET", testServerAgent.URL+"/"+DelegationProxy+"?uri="+testServerAgent.URL+"/_test/", nil)
	// assert.NoError(t, err)
	// request.Header.Add("Origin", "https://example.org/")
	// response, err := httpClient.Do(request)
	// assert.NoError(t, err)
	// assert.Equal(t, 200, response.StatusCode)
	// assert.Contains(t, response.Header.Get("Content-Type"), "text/turtle")
	// body, err := ioutil.ReadAll(response.Body)
	// assert.NoError(t, err)
	// response.Body.Close()
	// println("User:", response.Header.Get("User"))
	// assert.Contains(t, string(body), "<http://www.w3.org/ns/ldp#BasicContainer>")
}
