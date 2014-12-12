package gold

import (
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
)

var (
	handler = NewServer(GetServerRoot(), false)
)

func TestMKCOL(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("MKCOL", "/_test", nil)
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		response = r.Put("/_test/abc", "text/turtle", "<a> <b> <c>.")
		assert.Equal(t, 201, response.StatusCode)

		request, _ = http.NewRequest("MKCOL", "/_test/abc", nil)
		response = r.Do(request)
		assert.Equal(t, 409, response.StatusCode)

		request, _ = http.NewRequest("GET", "/_test", nil)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestSkin(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "text/html")
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Contains(t, response.RawResponse.Header.Get("Content-Type"), "text/html")

		request, _ = http.NewRequest("PUT", "/_test/index.html", strings.NewReader("<html>Hello world!</html>"))
		request.Header.Add("Content-Type", "text/html")
		response = r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		request, _ = http.NewRequest("GET", "/_test/index.html", nil)
		request.Header.Add("Accept", "text/html")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Contains(t, response.RawResponse.Header.Get("Content-Type"), "text/html")
		assert.Contains(t, response.Body, "<html")
	})
}

func TestWebContent(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("PUT", "/_test/alert.js", strings.NewReader("alert('test');"))
		request.Header.Add("Content-Type", "application/javascript")
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		request, _ = http.NewRequest("PUT", "/_test/text.txt", strings.NewReader("foo bar"))
		request.Header.Add("Content-Type", "text/txt")
		response = r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		request, _ = http.NewRequest("PUT", "/_test/reset.css", strings.NewReader("* { padding: 0; }"))
		request.Header.Add("Content-Type", "text/css")
		response = r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		request, _ = http.NewRequest("GET", "/_test/alert.js", nil)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Contains(t, response.RawResponse.Header.Get("Content-Type"), "application/javascript")

		request, _ = http.NewRequest("GET", "/_test/text.txt", nil)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Contains(t, response.RawResponse.Header.Get("Content-Type"), "text/plain")

		request, _ = http.NewRequest("GET", "/_test/reset.css", nil)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Contains(t, response.RawResponse.Header.Get("Content-Type"), "text/css; charset=utf-8")

		assert.Equal(t, 200, r.Delete("/_test/alert.js", "", "").StatusCode)
		assert.Equal(t, 200, r.Delete("/_test/reset.css", "", "").StatusCode)
		assert.Equal(t, 200, r.Delete("/_test/text.txt", "", "").StatusCode)
	})
}

func TestHTMLIndex(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("HEAD", "/_test/index.html", nil)
		request.Header.Add("Accept", "text/html")
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)

		request, _ = http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "text/html")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		//		assert.Contains(t, response.RawResponse.Header.Get("Content-Type"), "text/html")
		//		assert.Equal(t, response.Body, "<html>Hello world!</html>")

		request, _ = http.NewRequest("HEAD", "/_test/", nil)
		request.Header.Add("Accept", "text/html")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, request.URL.String()+"index.html,meta", ParseLinkHeader(response.RawResponse.Header.Get("Link")).MatchRel("meta"))
		assert.Equal(t, request.URL.String()+"index.html,acl", ParseLinkHeader(response.RawResponse.Header.Get("Link")).MatchRel("acl"))

		assert.Equal(t, 200, r.Delete("/_test/index.html", "", "").StatusCode)
	})
}

func TestPathInfo(t *testing.T) {
	path := testServer.URL + "/_test/"
	sroot := GetServerRoot()

	p, err := handler.pathInfo("")
	assert.NotNil(t, err)

	p, err = handler.pathInfo(testServer.URL + "/")
	assert.Nil(t, err)
	assert.Equal(t, testServer.URL+"/", p.Uri)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "", p.Path)
	assert.Equal(t, sroot, p.File)
	assert.Equal(t, testServer.URL+"/"+ACLSuffix, p.AclUri)
	assert.Equal(t, sroot+ACLSuffix, p.AclFile)
	assert.Equal(t, testServer.URL+"/"+METASuffix, p.MetaUri)
	assert.Equal(t, sroot+METASuffix, p.MetaFile)

	p, err = handler.pathInfo(path)
	assert.Nil(t, err)
	assert.Equal(t, path, p.Uri)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "_test/", p.Path)
	assert.Equal(t, sroot+"_test/", p.File)
	assert.Equal(t, path+ACLSuffix, p.AclUri)
	assert.Equal(t, sroot+"_test/"+ACLSuffix, p.AclFile)
	assert.Equal(t, path+METASuffix, p.MetaUri)
	assert.Equal(t, sroot+"_test/"+METASuffix, p.MetaFile)

	p, err = handler.pathInfo(path + "abc")
	assert.Nil(t, err)
	assert.Equal(t, path+"abc", p.Uri)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "_test/abc", p.Path)
	assert.Equal(t, sroot+"_test/abc", p.File)
	assert.Equal(t, path+"abc"+ACLSuffix, p.AclUri)
	assert.Equal(t, sroot+"_test/abc"+ACLSuffix, p.AclFile)
	assert.Equal(t, path+"abc"+METASuffix, p.MetaUri)
	assert.Equal(t, sroot+"_test/abc"+METASuffix, p.MetaFile)

	p, err = handler.pathInfo(path + ACLSuffix)
	assert.Nil(t, err)
	assert.Equal(t, path+ACLSuffix, p.Uri)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "_test/"+ACLSuffix, p.Path)
	assert.Equal(t, sroot+"_test/"+ACLSuffix, p.File)
	assert.Equal(t, path+ACLSuffix, p.AclUri)
	assert.Equal(t, sroot+"_test/"+ACLSuffix, p.AclFile)
	assert.Equal(t, path+ACLSuffix, p.MetaUri)
	assert.Equal(t, sroot+"_test/"+ACLSuffix, p.MetaFile)

	p, err = handler.pathInfo(path + METASuffix)
	assert.Nil(t, err)
	assert.Equal(t, path+METASuffix, p.Uri)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "_test/"+METASuffix, p.Path)
	assert.Equal(t, sroot+"_test/"+METASuffix, p.File)
	assert.Equal(t, path+METASuffix+ACLSuffix, p.AclUri)
	assert.Equal(t, sroot+"_test/"+METASuffix+ACLSuffix, p.AclFile)
	assert.Equal(t, path+METASuffix, p.MetaUri)
	assert.Equal(t, sroot+"_test/"+METASuffix, p.MetaFile)
}

func TestOPTIONS(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("OPTIONS", "/", nil)
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("Access-Control-Request-Headers", "Triples")
		request.Header.Add("Access-Control-Request-Method", "PATCH")
		response := r.Do(request)
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestOPTIONSOrigin(t *testing.T) {
	origin := "http://localhost:1234"
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("OPTIONS", "/", nil)
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("Origin", origin)
		response := r.Do(request)
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.RawResponse.Header.Get("Access-Control-Allow-Origin"), origin)
	})
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
	assert.Equal(t, testServer.URL+"/_test/dir/"+METASuffix, metaURI)

	aclURI := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	assert.Equal(t, testServer.URL+"/_test/dir/"+ACLSuffix, aclURI)

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
	assert.Equal(t, newLDPC+METASuffix, metaURI)

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

	request, err = http.NewRequest("GET", metaURI, nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.Equal(t, response.Header.Get("Triples"), "1")

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
	newLDPR := response.Header.Get("Location")

	request, err = http.NewRequest("GET", newLDPR, nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, response.Header.Get("Triples"), "1")
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
	assert.Equal(t, 409, response.StatusCode)

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
	assert.Equal(t, "1", response.Header.Get("Triples"))
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	assert.Equal(t, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<>\n    a <http://example.org/two> .\n\n", string(body))

	request, err = http.NewRequest("DELETE", newLDPR, nil)
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func TestLDPGetLDPC(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "text/turtle")
		response := r.Do(request)
		assert.NoError(t, err)
		assert.Equal(t, 200, response.StatusCode)

		g := NewGraph(testServer.URL + "/_test/")
		g.Parse(strings.NewReader(response.Body), "text/turtle")
		assert.NotNil(t, g.One(NewResource(testServer.URL+"/_test/"), NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), NewResource("http://www.w3.org/ns/ldp#BasicContainer")))
	})
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

// func TestLDPLinkHeaders(t *testing.T) {
// 	request, err := http.NewRequest("HEAD", testServer.URL+"/_test/", nil)
// 	assert.NoError(t, err)
// 	response, err := httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#Resource"))
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#BasicContainer"))

// 	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/abc", nil)
// 	assert.NoError(t, err)
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#Resource"))
// 	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#BasicContainer"))

// 	request, err = http.NewRequest("OPTIONS", testServer.URL+"/_test/", nil)
// 	assert.NoError(t, err)
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#Resource"))
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#BasicContainer"))

// 	request, err = http.NewRequest("OPTIONS", testServer.URL+"/_test/abc", nil)
// 	assert.NoError(t, err)
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#Resource"))
// 	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#BasicContainer"))

// 	request, err = http.NewRequest("GET", testServer.URL+"/_test/", nil)
// 	assert.NoError(t, err)
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#Resource"))
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#BasicContainer"))

// 	request, err = http.NewRequest("GET", testServer.URL+"/_test/abc", nil)
// 	assert.NoError(t, err)
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#Resource"))
// 	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#BasicContainer"))

// 	request, err = http.NewRequest("PUT", testServer.URL+"/_test/abc", nil)
// 	assert.NoError(t, err)
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#Resource"))
// 	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#BasicContainer"))

// 	request, err = http.NewRequest("POST", testServer.URL+"/_test/abc", nil)
// 	assert.NoError(t, err)
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#Resource"))
// 	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#BasicContainer"))

// 	request, err = http.NewRequest("POST", testServer.URL+"/_test/", nil)
// 	assert.NoError(t, err)
// 	response, err = httpClient.Do(request)
// 	assert.NoError(t, err)
// 	assert.True(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#Resource"))
// 	assert.False(t, ParseLinkHeader(strings.Join(response.Header["Link"], ", ")).MatchUri("http://www.w3.org/ns/ldp#BasicContainer"))
// 	newLDPR := response.Header.Get("Location")

// 	request, err = http.NewRequest("DELETE", newLDPR, nil)
// 	response, err = httpClient.Do(request)
// 	response.Body.Close()
// 	assert.NoError(t, err)
// 	assert.Equal(t, 200, response.StatusCode)
// }

func TestStreaming(t *testing.T) {
	Streaming = true
	defer func() {
		Streaming = false
	}()
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("PUT", "/_test/abc", strings.NewReader("<a> <b> <c> ."))
		request.Header.Add("Content-Type", "text/turtle")
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		response = r.Get("/_test/abc")
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c> .\n\n", response.Body)

		request, _ = http.NewRequest("PUT", "/_test/abc", nil)
		response = r.Do(request)
		assert.Equal(t, 201, response.StatusCode)
	})
}

func TestETag(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		etag := "\"3520a395fdacd680ba71627e3ef6b13a\""
		response := r.Get("/_test/")
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, etag, response.RawResponse.Header.Get("ETag"))

		etag = "\"d41d8cd98f00b204e9800998ecf8427e\""
		response = r.Get("/_test/abc")
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, etag, response.RawResponse.Header.Get("ETag"))
	})
}

func TestPOSTSPARQL(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("POST", "/_test/abc", strings.NewReader("INSERT DATA { <a> <b> <c>, <c0> . }"))
		request.Header.Add("Content-Type", "application/sparql-update")
		response := r.Do(request)
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "2", response.RawResponse.Header.Get("Triples"))

		request, _ = http.NewRequest("POST", "/_test/abc", strings.NewReader("DELETE DATA { <a> <b> <c> . }"))
		request.Header.Add("Content-Type", "application/sparql-update")
		response = r.Do(request)
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "1", response.RawResponse.Header.Get("Triples"))
	})
}

func TestPOSTTurtle(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Post("/_test/abc", "text/turtle", "<a> <b> <c1> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "2", response.RawResponse.Header.Get("Triples"))

		response = r.Post("/_test/abc", "text/turtle", "<a> <b> <c2> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "3", response.RawResponse.Header.Get("Triples"))

		request, _ := http.NewRequest("GET", "/_test/abc", nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "3", response.RawResponse.Header.Get("Triples"))
		assert.Equal(t, response.Body, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c0>, <c1>, <c2> .\n\n")
	})
}

func TestPATCHJson(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("PATCH", "/_test/abc", strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c"}]}}`))
		request.Header.Add("Content-Type", "application/json")
		response := r.Do(request)
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)

		request, _ = http.NewRequest("GET", "/_test/abc", nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.Body, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c> .\n\n")
		assert.Equal(t, response.RawResponse.Header.Get("Triples"), "1")
	})
}

func TestPUTTurtle(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Put("/_test/abc", "text/turtle", "<d> <e> <f> ; <h> <i> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 201, response.StatusCode)

		request, _ := http.NewRequest("GET", "/_test/abc", nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.Body, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<d>\n    <e> <f> ;\n    <h> <i> .\n\n")
	})
}

func TestHEAD(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("HEAD", "/_test/abc", nil)
		response := r.Do(request)
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "2", response.RawResponse.Header.Get("Triples"))
		assert.NotEmpty(t, response.RawResponse.Header.Get("Content-Length"))
	})
}

func TestIfMatch(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("HEAD", "/_test/abc", nil)
		response := r.Do(request)

		ETag := response.RawResponse.Header.Get("ETag")
		newTag := ETag[:len(ETag)-1] + "1\""

		request, _ = http.NewRequest("HEAD", "/_test/abc", nil)
		request.Header.Add("If-Match", ETag+", "+newTag)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)

		request, _ = http.NewRequest("HEAD", "/_test/abc", nil)
		request.Header.Add("If-Match", newTag)
		response = r.Do(request)
		assert.Equal(t, 412, response.StatusCode)

		request, _ = http.NewRequest("PATCH", "/_test/abc", strings.NewReader("<d> <e> <f> ."))
		request.Header.Add("Content-Type", "text/turtle")
		request.Header.Add("If-Match", newTag)
		response = r.Do(request)
		assert.Equal(t, 412, response.StatusCode)

		request, _ = http.NewRequest("POST", "/_test/abc", strings.NewReader("<d> <e> <f> ."))
		request.Header.Add("Content-Type", "text/turtle")
		request.Header.Add("If-Match", newTag)
		response = r.Do(request)
		assert.Equal(t, 412, response.StatusCode)

		response = r.Put("/_test/abc", "text/turtle", "<d> <e> <f> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 201, response.StatusCode)
	})
}

func TestIfNoneMatch(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("HEAD", "/_test/abc", nil)
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)

		ETag := response.RawResponse.Header.Get("ETag")
		newTag := ETag[:len(ETag)-1] + "1\""

		request, _ = http.NewRequest("HEAD", "/_test/abc", nil)
		request.Header.Add("If-None-Match", ETag)
		response = r.Do(request)
		assert.Equal(t, 304, response.StatusCode)

		request, _ = http.NewRequest("HEAD", "/_test/abc", nil)
		request.Header.Add("If-None-Match", ETag+", "+newTag)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)

		request, _ = http.NewRequest("PUT", "/_test/abc", strings.NewReader("<d> <e> <f> ."))
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("If-None-Match", ETag)
		response = r.Do(request)
		assert.Equal(t, 412, response.StatusCode)

		request, _ = http.NewRequest("POST", "/_test/abc", strings.NewReader("<d> <e> <f> ."))
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("If-None-Match", ETag)
		response = r.Do(request)
		assert.Equal(t, 412, response.StatusCode)

		request, _ = http.NewRequest("PATCH", "/_test/abc", strings.NewReader("<d> <e> <f> ."))
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("If-None-Match", ETag)
		response = r.Do(request)
		assert.Equal(t, 412, response.StatusCode)

		request, _ = http.NewRequest("PUT", "/_test/abc", strings.NewReader("<d> <e> <f> ."))
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("If-None-Match", newTag)
		response = r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

	})
}

func TestGetJsonLd(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/_test/abc", nil)
		request.Header.Add("Accept", "application/ld+json")
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "1", response.RawResponse.Header.Get("Triples"))
		d := r.Url("/_test/d")
		e := r.Url("/_test/e")
		f := r.Url("/_test/f")
		assert.Equal(t, response.Body, fmt.Sprintf(`[{"@id":"http://%s","http://%s":[{"@id":"http://%s"}]}]`, d, e, f))

		request, _ = http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "application/ld+json")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "9", response.RawResponse.Header.Get("Triples"))
	})
}

func TestPOSTForm(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("POST", "/_test/abc", nil)
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		response := r.Do(request)
		assert.Equal(t, 415, response.StatusCode)
	})
}

func TestPOSTMultiForm(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
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

		request, _ := http.NewRequest("POST", "", bodyReader)
		request.Header.Add("Content-Type", "multipart/form-data; boundary="+multiWriter.Boundary())
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		response = r.Delete("/img.jpg", "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
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
	assert.Equal(t, g.One(f, ns.rdf.Get("type"), ns.stat.Get("File")).Object, ns.stat.Get("File"))

	d := NewResource(testServer.URL + "/_test/dir/")
	assert.Equal(t, g.One(d, ns.rdf.Get("type"), ns.stat.Get("Directory")).Object, ns.stat.Get("Directory"))
	assert.NotNil(t, g.One(d, ns.stat.Get("size"), nil))
	assert.NotNil(t, g.One(d, ns.stat.Get("mtime"), nil))
}

func TestGlob(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Post("/_test/1", "text/turtle", "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/one>;\n"+
			"    <http://example.org/b> <#c> .\n    <#c> a <http://example.org/e> .")
		assert.Equal(t, 201, response.StatusCode)

		response = r.Post("/_test/2", "text/turtle", "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/two>.")
		assert.Equal(t, 201, response.StatusCode)

		request, _ := http.NewRequest("GET", "/_test/*", nil)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)

		g := NewGraph(testServer.URL + "/_test/")
		g.Parse(strings.NewReader(response.Body), "text/turtle")

		assert.NotEmpty(t, g)
		assert.Equal(t, g.One(NewResource(testServer.URL+"/_test/1"), ns.rdf.Get("type"), NewResource("http://example.org/one")).Object, NewResource("http://example.org/one"))
		assert.Equal(t, g.One(NewResource(testServer.URL+"/_test/1#c"), ns.rdf.Get("type"), NewResource("http://example.org/e")).Object, NewResource("http://example.org/e"))
		assert.Equal(t, g.One(NewResource(testServer.URL+"/_test/2"), ns.rdf.Get("type"), NewResource("http://example.org/two")).Object, NewResource("http://example.org/two"))

		assert.Equal(t, 200, r.Delete("/_test/1", "", "").StatusCode)
		assert.Equal(t, 200, r.Delete("/_test/2", "", "").StatusCode)
	})
}

func TestDELETEFiles(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		assert.Equal(t, 200, r.Delete("/_test/abc", "", "").StatusCode)
	})
}

func TestDELETEFolders(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Delete("/_test/dir", "", "")
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)

		response = r.Delete("/_test", "", "")
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)

		response = r.Get("/_test")
		assert.Equal(t, 404, response.StatusCode)

		response = r.Delete("/_test", "", "")
		assert.Equal(t, 404, response.StatusCode)

		response = r.Delete("/", "", "")
		assert.Equal(t, 500, response.StatusCode)
	})
}

func TestInvalidMethod(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("TEST", "/test", nil)
		response := r.Do(request)
		assert.Equal(t, 405, response.StatusCode)
	})
}

func TestInvalidAccept(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/test", nil)
		request.Header.Add("Accept", "text/csv")
		response := r.Do(request)
		assert.Equal(t, 406, response.StatusCode)
	})
}

func TestInvalidContent(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Post("/test", "text/csv", "a\tb\tc\n")
		assert.Equal(t, 415, response.StatusCode)
	})
}

func TestRawContent(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		path := "./tests/img.jpg"
		file, err := os.Open(path)
		defer file.Close()
		assert.NoError(t, err)
		stat, err := os.Stat(path)
		data := make([]byte, stat.Size())
		_, err = file.Read(data)
		assert.NoError(t, err)
		ctype := "image/jpeg"

		response := r.Put("/test.raw", ctype, string(data))
		assert.Equal(t, 201, response.StatusCode)
		response = r.Get("/test.raw")
		assert.Equal(t, response.StatusCode, 200)
		assert.Equal(t, response.RawResponse.Header.Get(HCType), ctype)
		assert.Equal(t, len(response.Body), stat.Size())
		assert.Equal(t, 200, r.Delete("/test.raw", "", "").StatusCode)
	})
}

func BenchmarkPUT(b *testing.B) {
	e := 0
	testflight.WithServer(handler, func(r *testflight.Requester) {
		for i := 0; i < b.N; i++ {
			x := r.Put("/_bench/test", "text/turtle", "<d> <e> <f> .")
			if x.StatusCode != 201 {
				e += 1
			}
		}
	})
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkPUTNew(b *testing.B) {
	e := 0
	testflight.WithServer(handler, func(r *testflight.Requester) {
		for i := 0; i < b.N; i++ {
			x := r.Put(fmt.Sprintf("/_bench/test%d", i), "text/turtle", "<d> <e> <f> .")
			if x.StatusCode != 201 {
				e += 1
			}
		}
	})
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkPATCH(b *testing.B) {
	e := 0
	testflight.WithServer(handler, func(r *testflight.Requester) {
		for i := 0; i < b.N; i++ {
			request, _ := http.NewRequest("PATCH", "/_bench/test", strings.NewReader(`{"a":{"b":[{"type":"literal","value":"`+fmt.Sprintf("%d", b.N)+`"}]}}`))
			request.Header.Add("Content-Type", "application/json")
			if r := r.Do(request); r.StatusCode != 200 {
				e += 1
			}
		}
	})
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkGETjson(b *testing.B) {
	e := 0
	testflight.WithServer(handler, func(r *testflight.Requester) {
		for i := 0; i < b.N; i++ {
			request, _ := http.NewRequest("GET", "/_bench/test", nil)
			request.Header.Add("Content-Type", "application/json")
			if r := r.Do(request); r.StatusCode != 200 {
				e += 1
			}
		}
	})
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkGETturtle(b *testing.B) {
	e := 0
	testflight.WithServer(handler, func(r *testflight.Requester) {
		for i := 0; i < b.N; i++ {
			request, _ := http.NewRequest("GET", "/_bench/test", nil)
			request.Header.Add("Content-Type", "text/turtle")
			if r := r.Do(request); r.StatusCode != 200 {
				e += 1
			}
		}
	})
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}

func BenchmarkGETxml(b *testing.B) {
	e := 0
	testflight.WithServer(handler, func(r *testflight.Requester) {
		for i := 0; i < b.N; i++ {
			request, _ := http.NewRequest("GET", "/_bench/test", nil)
			request.Header.Add("Accept", "application/rdf+xml")
			if r := r.Do(request); r.StatusCode != 200 {
				fmt.Println(r.StatusCode)
				e += 1
			}
		}
	})
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}
