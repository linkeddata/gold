package gold

import (
	"crypto/rsa"
	"crypto/tls"
	// "errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	user1, user2         string
	user1g, user2g       *Graph
	user1k, user2k       *rsa.PrivateKey
	user1p, user2p       *rsa.PublicKey
	user1h, user2h       *http.Client
	user1cert, user2cert *tls.Certificate
	testServer           *httptest.Server
	config               *ServerConfig
	handler              *Server
)

func init() {
	config = NewServerConfig()
	handler = NewServer(config)

	testServer = httptest.NewUnstartedServer(handler)
	testServer.TLS = new(tls.Config)
	testServer.TLS.ClientAuth = tls.RequestClientCert
	testServer.TLS.NextProtos = []string{"http/1.1"}
	testServer.StartTLS()
	testServer.URL = strings.Replace(testServer.URL, "127.0.0.1", "localhost", 1)
}

// func noRedirect(req *http.Request, via []*http.Request) error {
// 	return errors.New("Don't redirect!")
// }

func TestHSTS(t *testing.T) {
	request, err := http.NewRequest("HEAD", testServer.URL+"/", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, "max-age=63072000; includeSubDomains", response.Header.Get("Strict-Transport-Security"))
}

func TestMKCOL(t *testing.T) {
	request, err := http.NewRequest("MKCOL", testServer.URL+"/_test", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/abc", strings.NewReader("<a> <b> <c>."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("MKCOL", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 409, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestOPTIONS(t *testing.T) {
	request, err := http.NewRequest("OPTIONS", testServer.URL+"/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("Access-Control-Request-Method", "PATCH")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Empty(t, string(body))
	assert.Equal(t, 200, response.StatusCode)
}

func TestOPTIONSOrigin(t *testing.T) {
	origin := "http://localhost:1234"
	request, err := http.NewRequest("OPTIONS", testServer.URL+"/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("Origin", origin)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, response.Header.Get("Access-Control-Allow-Origin"), origin)
}

func TestURIwithSpaces(t *testing.T) {
	request, err := http.NewRequest("PUT", testServer.URL+"/_test/file name", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/file name", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestURIwithWeirdChars(t *testing.T) {
	request, err := http.NewRequest("PUT", testServer.URL+"/_test/file name + %23frag", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/file name + %23frag", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestIndexHTMLFile(t *testing.T) {
	request, err := http.NewRequest("PUT", testServer.URL+"/_test/index.html", strings.NewReader("<html>Hello world!</html>"))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/html")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/html")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Contains(t, response.Header.Get("Content-Type"), "text/html")
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Contains(t, string(body), "<html>Hello world!</html>")
	assert.Equal(t, request.URL.String()+"index.html"+config.MetaSuffix, ParseLinkHeader(response.Header.Get("Link")).MatchRel("meta"))
	assert.Equal(t, request.URL.String()+"index.html"+config.ACLSuffix, ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl"))
}

func TestWebContent(t *testing.T) {
	request, err := http.NewRequest("PUT", testServer.URL+"/_test/alert.js", strings.NewReader("alert('test');"))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/javascript")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/text.txt", strings.NewReader("foo bar"))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/txt")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/reset.css", strings.NewReader("* { padding: 0; }"))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/css")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/alert.js", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Contains(t, response.Header.Get("Content-Type"), "application/javascript")

	request, err = http.NewRequest("GET", testServer.URL+"/_test/text.txt", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Contains(t, response.Header.Get("Content-Type"), "text/plain")

	request, err = http.NewRequest("GET", testServer.URL+"/_test/reset.css", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Contains(t, response.Header.Get("Content-Type"), "text/css; charset=utf-8")

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/alert.js", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/reset.css", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/text.txt", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/index.html", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestRedirectSignUpWithVhosts(t *testing.T) {
	// test vhosts
	testServer1 := httptest.NewUnstartedServer(handler1)
	testServer1.TLS = new(tls.Config)
	testServer1.TLS.ClientAuth = tls.RequestClientCert
	testServer1.TLS.NextProtos = []string{"http/1.1"}
	testServer1.StartTLS()

	request, err := http.NewRequest("GET", testServer1.URL, nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/html")
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, 404, response.StatusCode)
	assert.NotEmpty(t, string(body))

	request, err = http.NewRequest("GET", testServer1.URL+"/dir/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/html")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 404, response.StatusCode)

	request, err = http.NewRequest("GET", testServer1.URL+"/file", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/html")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 404, response.StatusCode)
}

func TestRedirectToSlashContainer(t *testing.T) {
	transport := http.Transport{}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	request, err := http.NewRequest("GET", testServer.URL+"/_test", nil)
	assert.NoError(t, err)
	response, err := transport.RoundTrip(request)
	assert.NoError(t, err)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, 301, response.StatusCode)
	assert.Equal(t, testServer.URL+"/_test/", response.Header.Get("Location"))

	request, err = http.NewRequest("GET", testServer.URL+"/_test", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/html")
	response, err = transport.RoundTrip(request)
	assert.NoError(t, err)
	body, _ = ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, 301, response.StatusCode)
	assert.Equal(t, testServer.URL+"/_test/", response.Header.Get("Location"))
	assert.NotEmpty(t, string(body))
}

func TestRedirectToDirApp(t *testing.T) {
	transport := http.Transport{}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	request, err := http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/html")
	response, err := transport.RoundTrip(request)
	assert.NoError(t, err)
	assert.Equal(t, 303, response.StatusCode)
	assert.True(t, strings.HasPrefix(response.Header.Get("Location"), handler.Config.DirApp))
}

func TestLDPPUTContainer(t *testing.T) {
	request, err := http.NewRequest("PUT", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 406, response.StatusCode)

	describedURI := ParseLinkHeader(response.Header.Get("Link")).MatchRel("describedby")
	assert.NotNil(t, describedURI)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/dir", nil)
	assert.NoError(t, err)
	request.Header.Add("Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	metaURI := ParseLinkHeader(response.Header.Get("Link")).MatchRel("meta")
	assert.Equal(t, testServer.URL+"/_test/dir/"+config.MetaSuffix, metaURI)

	aclURI := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	assert.Equal(t, testServer.URL+"/_test/dir/"+config.ACLSuffix, aclURI)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/dir/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestLDPPostLDPC(t *testing.T) {
	request, err := http.NewRequest("POST", testServer.URL+"/_test/", strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> .\n\n<> a <http://example.org/ldpc>."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("Slug", "ldpc")
	request.Header.Add("Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(response.Body)
	assert.Equal(t, 201, response.StatusCode, string(body))
	response.Body.Close()
	newLDPC := response.Header.Get("Location")
	assert.NotEmpty(t, newLDPC)

	metaURI := ParseLinkHeader(response.Header.Get("Link")).MatchRel("meta")
	assert.Equal(t, newLDPC+config.MetaSuffix, metaURI)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	body, err = ioutil.ReadAll(response.Body)
	assert.NoError(t, err)
	response.Body.Close()

	g := NewGraph(testServer.URL + "/_test/")
	g.Parse(strings.NewReader(string(body)), "text/turtle")
	assert.NotNil(t, g.One(NewResource(testServer.URL+"/_test/"), NewResource("http://www.w3.org/ns/ldp#contains"), NewResource(newLDPC)))
	assert.NotNil(t, g.One(NewResource(newLDPC), NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://example.org/ldpc")))
	assert.NotNil(t, g.One(NewResource(newLDPC), NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer")))
	request, err = http.NewRequest("HEAD", metaURI, nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", metaURI, nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", newLDPC, nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestLDPPostLDPRWithSlug(t *testing.T) {
	request, err := http.NewRequest("POST", testServer.URL+"/_test/", strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/two>."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("Slug", "ldpr")
	request.Header.Add("Link", "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"")
	response, err := httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)
	oldLDPR := response.Header.Get("Location")

	request, err = http.NewRequest("GET", oldLDPR, nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	body, err := ioutil.ReadAll(response.Body)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, string(body), "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<>\n    a <http://example.org/two> .\n\n")

	request, err = http.NewRequest("POST", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("Slug", "ldpr")
	request.Header.Add("Link", "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)
	newLDPR := response.Header.Get("Location")
	assert.True(t, strings.Contains(newLDPR, "ldpr-"))

	request, err = http.NewRequest("DELETE", oldLDPR, nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", newLDPR, nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestLDPPostLDPRNoSlug(t *testing.T) {
	request, err := http.NewRequest("POST", testServer.URL+"/_test/", strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/two>."))
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("Link", "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"")
	response, err := httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)
	newLDPR := response.Header.Get("Location")

	request, err = http.NewRequest("GET", newLDPR, nil)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, 6, len(filepath.Base(newLDPR)))
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<>\n    a <http://example.org/two> .\n\n", string(body))

	request, err = http.NewRequest("DELETE", newLDPR, nil)
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestLDPGetLDPR(t *testing.T) {
	resource_url := testServer.URL + "/_test/resource.ttl"

	request, err := http.NewRequest("PUT", resource_url, nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)

	request, err = http.NewRequest("GET", resource_url, nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)

	assert.Equal(t, "text/turtle", response.Header.Get("Content-Type"))

	request, err = http.NewRequest("DELETE", resource_url, nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
}

func TestLDPGetLDPC(t *testing.T) {
	request, err := http.NewRequest("HEAD", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	meta := ParseLinkHeader(response.Header.Get("Link")).MatchRel("meta")

	request, err = http.NewRequest("PUT", meta, strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/two>."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()

	g := NewGraph(testServer.URL + "/_test/")
	g.Parse(strings.NewReader(string(body)), "text/turtle")
	assert.Nil(t, g.One(NewResource(meta), nil, nil))
	assert.NotNil(t, g.One(NewResource(testServer.URL+"/_test/"), NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer")))

	request, err = http.NewRequest("DELETE", meta, nil)
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestLDPPreferContainmentHeader(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("Prefer", "return=representation; omit=\"http://www.w3.org/ns/ldp#PreferEmptyContainer\", return=representation; include=\"http://www.w3.org/ns/ldp#PreferContainment\"")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "return=representation", response.Header.Get("Preference-Applied"))

	g := NewGraph(testServer.URL + "/_test/")

	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	g.Parse(strings.NewReader(string(body)), "text/turtle")
	assert.NotNil(t, g.One(NewResource(testServer.URL+"/_test/"), NewResource("http://www.w3.org/ns/ldp#contains"), nil))

	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("Prefer", "return=representation; include=\"http://www.w3.org/ns/ldp#PreferEmptyContainer\", return=representation; omit=\"http://www.w3.org/ns/ldp#PreferContainment\"")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)

	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "return=representation", response.Header.Get("Preference-Applied"))
	body, err = ioutil.ReadAll(response.Body)
	response.Body.Close()
	g = NewGraph(testServer.URL + "/_test/")
	g.Parse(strings.NewReader(string(body)), "text/turtle")
	assert.Nil(t, g.One(NewResource(testServer.URL+"/_test/"), NewResource("http://www.w3.org/ns/ldp#contains"), nil))
}

func TestLDPPreferEmptyHeader(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("Prefer", "return=representation; omit=\"http://www.w3.org/ns/ldp#PreferEmptyContainer\"")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "return=representation", response.Header.Get("Preference-Applied"))

	g := NewGraph(testServer.URL + "/_test/")
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	g.Parse(strings.NewReader(string(body)), "text/turtle")
	assert.NotNil(t, g.One(NewResource(testServer.URL+"/_test/abc"), nil, nil))

	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("Prefer", "return=representation; include=\"http://www.w3.org/ns/ldp#PreferEmptyContainer\"")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "return=representation", response.Header.Get("Preference-Applied"))

	g = NewGraph(testServer.URL + "/_test/")
	body, err = ioutil.ReadAll(response.Body)
	response.Body.Close()
	g.Parse(strings.NewReader(string(body)), "text/turtle")
	assert.Nil(t, g.One(NewResource("/_test/abc"), nil, nil))
}

/* Disabled tests until the LDPWG decides on which resources the Link headers apply. */

func TestLDPLinkHeaders(t *testing.T) {
	request, err := http.NewRequest("HEAD", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#Resource"))
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#BasicContainer"))

	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#Resource"))
	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#BasicContainer"))

	request, err = http.NewRequest("OPTIONS", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#Resource"))
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#BasicContainer"))

	request, err = http.NewRequest("OPTIONS", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#Resource"))
	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#BasicContainer"))

	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#Resource"))
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#BasicContainer"))

	request, err = http.NewRequest("GET", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#Resource"))
	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#BasicContainer"))

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Header.Get("Location"))
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#Resource"))
	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#BasicContainer"))

	request, err = http.NewRequest("POST", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#BasicContainer"))

	request, err = http.NewRequest("POST", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#Resource"))
	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchURI("http://www.w3.org/ns/ldp#BasicContainer"))
	newLDPR := response.Header.Get("Location")

	request, err = http.NewRequest("DELETE", newLDPR, nil)
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestStreaming(t *testing.T) {
	Streaming = true
	defer func() {
		Streaming = false
	}()
	request, err := http.NewRequest("PUT", testServer.URL+"/_test/abc", strings.NewReader("<a> <b> <c> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c> .\n\n", string(body))

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestPOSTSPARQL(t *testing.T) {
	request, err := http.NewRequest("POST", testServer.URL+"/_test/abc", strings.NewReader("INSERT DATA { <a> <b> <c>, <c0> . }"))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/sparql-update")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+"/_test/abc", strings.NewReader("DELETE DATA { <a> <b> <c> . }"))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/sparql-update")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestPOSTTurtle(t *testing.T) {
	request, err := http.NewRequest("POST", testServer.URL+"/_test/abc", strings.NewReader("<a> <b> <c1> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+"/_test/abc", strings.NewReader("<a> <b> <c2> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c0>, <c1>, <c2> .\n\n", string(body))
}

func TestPATCHJson(t *testing.T) {
	request, err := http.NewRequest("PATCH", testServer.URL+"/_test/abc", strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c"}]}}`))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/json")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c> .\n\n", string(body))
}

func TestPATCHSPARQL(t *testing.T) {
	request, err := http.NewRequest("PATCH", testServer.URL+"/_test/abc", strings.NewReader(""))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/sparql-update")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.NotEmpty(t, string(body))
	assert.Equal(t, 400, response.StatusCode)

	sparqlData := `INSERT DATA { <http://a.com> <http://b.com> <http://c.com> . } ; INSERT DATA { <http://a.com> <http://b.com> "123"^^<http://www.w3.org/2001/XMLSchema#int> . }`
	request, err = http.NewRequest("PATCH", testServer.URL+"/_test/abc", strings.NewReader(sparqlData))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/sparql-update")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	body, err = ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Empty(t, string(body))
	assert.Equal(t, 200, response.StatusCode)

	g := NewGraph(testServer.URL + "/_test/abc")
	g.LoadURI(testServer.URL + "/_test/abc")
	assert.NotNil(t, g.One(NewResource("http://a.com"), NewResource("http://b.com"), NewResource("http://c.com")))

	sparqlData = `DELETE DATA { <http://a.com> <http://b.com> <http://c.com>  . }; DELETE DATA { <http://a.com> <http://b.com> "123"^^<http://www.w3.org/2001/XMLSchema#int> . }`
	request, err = http.NewRequest("PATCH", testServer.URL+"/_test/abc", strings.NewReader(sparqlData))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/sparql-update")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	body, err = ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Empty(t, string(body))
	assert.Equal(t, 200, response.StatusCode)

	g = NewGraph(testServer.URL + "/_test/abc")
	g.LoadURI(testServer.URL + "/_test/abc")
	assert.Nil(t, g.One(NewResource("http://a.com"), NewResource("http://b.com"), NewResource("http://c.com")))
}

func TestPATCHFailParse(t *testing.T) {
	sparqlData := `I { <a> <b> <c> . }`
	request, err := http.NewRequest("PATCH", testServer.URL+"/_test/abc", strings.NewReader(sparqlData))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/sparql-update")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestPATCHFileNoExist(t *testing.T) {
	file := "_test/fff"
	sparqlData := `INSERT DATA { <a> <b> <c> . }`

	_, err := os.Stat(file)
	assert.True(t, os.IsNotExist(err))

	request, err := http.NewRequest("PATCH", testServer.URL+"/"+file, strings.NewReader(sparqlData))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/sparql-update")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	g := NewGraph(testServer.URL + "/" + file)
	g.ReadFile(file)
	assert.Equal(t, 1, g.Len())
	data, err := g.Serialize(("text/turtle"))
	assert.NoError(t, err)
	assert.Equal(t, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c> .\n\n", data)

	// cleanup
	os.Remove(file)
}

func TestPUTTurtle(t *testing.T) {
	request, err := http.NewRequest("DELETE", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/abc", strings.NewReader("<d> <e> <f> ; <h> <i> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Empty(t, string(body))
	assert.NotEmpty(t, response.Header.Get("Location"))

	request, err = http.NewRequest("GET", testServer.URL+"/_test/abc", nil)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	body, err = ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<d>\n    <e> <f> ;\n    <h> <i> .\n\n", string(body))
}

func TestPUTRdf(t *testing.T) {
	for ext, ctype := range mimeRdfExt {
		request, err := http.NewRequest("PUT", testServer.URL+"/_test/abc"+ext, nil)
		assert.NoError(t, err)
		request.Header.Add("Content-Type", ctype)
		response, err := httpClient.Do(request)
		assert.NoError(t, err)
		assert.Equal(t, 201, response.StatusCode)

		request, err = http.NewRequest("DELETE", testServer.URL+"/_test/abc"+ext, nil)
		assert.NoError(t, err)
		response, err = httpClient.Do(request)
		assert.NoError(t, err)
		assert.Equal(t, 200, response.StatusCode)
	}
}

func TestHEAD(t *testing.T) {
	request, err := http.NewRequest("HEAD", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Empty(t, string(body))
	assert.NotEmpty(t, response.Header.Get("Content-Length"))
	assert.Equal(t, response.Header.Get("Content-Type"), "text/turtle")
}

func TestGetUnsupportedMediaType(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 415, response.StatusCode)
}

func TestAcceptHeaderWildcard(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "*/*")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.NotEmpty(t, string(body))
	assert.Equal(t, 200, response.StatusCode)
}

func TestCTypeServeDefault(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Body)
	assert.Equal(t, 200, response.StatusCode)
	assert.Contains(t, "text/turtle", response.Header.Get("Content-Type"))
	assert.NotEqual(t, "0", response.Header.Get("Content-Length"))
}

func TestCTypeFailForXHTMLXML(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/xml,application/xml,application/xhtml+xml,text/html;q=0.5,text/plain,image/png,/;q=0.1,application/rdf+xml,text/n3,text/turtle")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.NotEmpty(t, string(body))
	assert.Equal(t, 200, response.StatusCode)
	assert.NotContains(t, "application/xhtml+xml", response.Header.Get("Content-Type"))
}

func TestIfMatch(t *testing.T) {
	request, err := http.NewRequest("HEAD", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)

	ETag := response.Header.Get("ETag")
	newTag := ETag[:len(ETag)-1] + "1\""

	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("If-Match", ETag+", "+newTag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("If-Match", newTag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 412, response.StatusCode)

	request, err = http.NewRequest("PATCH", testServer.URL+"/_test/abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("If-Match", newTag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 412, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+"/_test/abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("If-Match", newTag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 412, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Empty(t, string(body))
	assert.Equal(t, 200, response.StatusCode)
}

func TestIfNoneMatch(t *testing.T) {
	request, err := http.NewRequest("HEAD", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	ETag := response.Header.Get("ETag")

	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("If-None-Match", ETag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 304, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("If-None-Match", ETag)
	request.Header.Add("Accept", "text/html")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	ETag = response.Header.Get("ETag")
	newTag := ETag[:len(ETag)-1] + "1\""

	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("If-None-Match", ETag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 304, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("If-None-Match", ETag+", "+newTag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("If-None-Match", ETag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 412, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+"/_test/abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("If-None-Match", ETag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 412, response.StatusCode)

	request, err = http.NewRequest("PATCH", testServer.URL+"/_test/abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("If-None-Match", ETag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 412, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	request.Header.Add("If-None-Match", newTag)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestGetJsonLd(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "application/ld+json")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()

	d := testServer.URL + "/_test/d"
	e := testServer.URL + "/_test/e"
	f := testServer.URL + "/_test/f"
	assert.Equal(t, fmt.Sprintf(`[{"@id":"%s","%s":[{"@id":"%s"}]}]`, d, e, f), string(body))

	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "application/ld+json")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestPOSTForm(t *testing.T) {
	request, err := http.NewRequest("POST", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 415, response.StatusCode)
}

func TestPOSTMultiForm(t *testing.T) {
	path := "tests/img.jpg"
	file, err := os.Open(path)
	defer file.Close()
	assert.NoError(t, err)

	bodyReader, bodyWriter := io.Pipe()
	multiWriter := multipart.NewWriter(bodyWriter)
	errChan := make(chan error, 1)
	go func() {
		defer bodyWriter.Close()
		part, err := multiWriter.CreateFormFile("file", filepath.Base(path))
		if err != nil {
			errChan <- err
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			errChan <- err
			return
		}
		errChan <- multiWriter.Close()
	}()

	request, err := http.NewRequest("POST", testServer.URL+"/_test/", bodyReader)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "multipart/form-data; boundary="+multiWriter.Boundary())
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)
	assert.Equal(t, testServer.URL+"/_test/img.jpg", response.Header.Get("Location"))

	request, err = http.NewRequest("DELETE", response.Header.Get("Location"), nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestLISTDIR(t *testing.T) {
	request, err := http.NewRequest("MKCOL", testServer.URL+"/_test/dir", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+"/_test/abc", strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/abc> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	g := NewGraph(testServer.URL + "/_test/")
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	g.Parse(strings.NewReader(string(body)), "text/turtle")

	f := NewResource(testServer.URL + "/_test/abc")
	assert.NotNil(t, g.One(f, ns.stat.Get("size"), nil))
	assert.NotNil(t, g.One(f, ns.stat.Get("mtime"), nil))
	assert.NotNil(t, g.One(f, ns.rdf.Get("type"), NewResource("http://example.org/abc")))
	assert.Equal(t, g.One(f, ns.rdf.Get("type"), NewResource("http://example.org/abc")).Object, NewResource("http://example.org/abc"))
	assert.Equal(t, g.One(f, ns.rdf.Get("type"), ns.ldp.Get("Resource")).Object, ns.ldp.Get("Resource"))

	d := NewResource(testServer.URL + "/_test/dir/")
	assert.Equal(t, g.One(d, ns.rdf.Get("type"), ns.ldp.Get("Container")).Object, ns.ldp.Get("Container"))
	assert.NotNil(t, g.One(d, ns.stat.Get("size"), nil))
	assert.NotNil(t, g.One(d, ns.stat.Get("mtime"), nil))
}

func TestGlob(t *testing.T) {
	request, err := http.NewRequest("PUT", testServer.URL+"/_test/1", strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/one>;\n"+
		"    <http://example.org/b> <#c> .\n    <#c> a <http://example.org/e> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+"/_test/2", strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/two>."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/*", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()

	g := NewGraph(testServer.URL + "/_test/")
	g.Parse(strings.NewReader(string(body)), "text/turtle")
	assert.NotEmpty(t, g)
	assert.Equal(t, g.One(NewResource(testServer.URL+"/_test/1"), ns.rdf.Get("type"), NewResource("http://example.org/one")).Object, NewResource("http://example.org/one"))
	assert.Equal(t, g.One(NewResource(testServer.URL+"/_test/2"), ns.rdf.Get("type"), NewResource("http://example.org/two")).Object, NewResource("http://example.org/two"))

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/1", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/2", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestDELETEFile(t *testing.T) {
	request, err := http.NewRequest("DELETE", testServer.URL+"/_test/abc", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestDELETEFolders(t *testing.T) {
	request, err := http.NewRequest("DELETE", testServer.URL+"/_test/dir", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 404, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/_test/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 404, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+"/", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 500, response.StatusCode)
}

func TestInvalidMethod(t *testing.T) {
	request, err := http.NewRequest("TEST", testServer.URL+"/test", nil)
	assert.NoError(t, err)
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 405, response.StatusCode)
}

func TestInvalidAccept(t *testing.T) {
	request, err := http.NewRequest("GET", testServer.URL+"/test", nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/csv")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 406, response.StatusCode)
}

func TestInvalidContent(t *testing.T) {
	request, err := http.NewRequest("POST", testServer.URL+"/test", strings.NewReader("a\tb\tc\n"))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/csv")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 415, response.StatusCode)
}

func TestRawContent(t *testing.T) {
	path := "./tests/img.jpg"
	file, err := os.Open(path)
	defer file.Close()
	assert.NoError(t, err)
	stat, err := os.Stat(path)
	data := make([]byte, stat.Size())
	_, err = file.Read(data)
	assert.NoError(t, err)

	request, err := http.NewRequest("PUT", testServer.URL+"/test.raw", strings.NewReader(string(data)))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "image/jpeg")
	response, err := httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+"/test.raw", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "image/jpeg", response.Header.Get(HCType))
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, stat.Size(), int64(len(string(body))))

	request, err = http.NewRequest("DELETE", testServer.URL+"/test.raw", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func BenchmarkPUT(b *testing.B) {
	e := 0
	for i := 0; i < b.N; i++ {
		request, _ := http.NewRequest("PUT", testServer.URL+"/_bench/test", strings.NewReader("<d> <e> <f> ."))
		request.Header.Add("Content-Type", "text/turtle")
		if response, _ := httpClient.Do(request); response.StatusCode != 201 {
			e++
		}
	}
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkPUTNew(b *testing.B) {
	e := 0
	for i := 0; i < b.N; i++ {
		request, _ := http.NewRequest("PUT", testServer.URL+fmt.Sprintf("/_bench/test%d", i), strings.NewReader("<d> <e> <f> ."))
		request.Header.Add("Content-Type", "text/turtle")
		if response, _ := httpClient.Do(request); response.StatusCode != 201 {
			e++
		}
	}
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkPATCH(b *testing.B) {
	e := 0
	for i := 0; i < b.N; i++ {
		request, _ := http.NewRequest("PATCH", testServer.URL+"/_bench/test", strings.NewReader(`{"a":{"b":[{"type":"literal","value":"`+fmt.Sprintf("%d", b.N)+`"}]}}`))
		request.Header.Add("Content-Type", "application/json")
		if response, _ := httpClient.Do(request); response.StatusCode != 200 {
			e++
		}
	}
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkGETjson(b *testing.B) {
	e := 0
	for i := 0; i < b.N; i++ {
		request, _ := http.NewRequest("GET", testServer.URL+"/_bench/test", nil)
		request.Header.Add("Content-Type", "application/json")
		if response, _ := httpClient.Do(request); response.StatusCode != 200 {
			e++
		}
	}
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkGETturtle(b *testing.B) {
	e := 0
	for i := 0; i < b.N; i++ {
		request, _ := http.NewRequest("GET", testServer.URL+"/_bench/test", nil)
		request.Header.Add("Content-Type", "text/turtle")
		if response, _ := httpClient.Do(request); response.StatusCode != 200 {
			e++
		}
	}
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkGETxml(b *testing.B) {
	e := 0
	for i := 0; i < b.N; i++ {
		request, _ := http.NewRequest("GET", testServer.URL+"/_bench/test", nil)
		request.Header.Add("Accept", "application/rdf+xml")
		if response, _ := httpClient.Do(request); response.StatusCode != 200 {
			e++
		}
	}
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}
