package gold

import (
	"fmt"
	"github.com/drewolson/testflight"
	rdf "github.com/kierdavis/argo"
	"github.com/stretchr/testify/assert"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	handler = NewServer(".", false)

	testDelete = true
)

func TestSkin(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/", nil)
		request.Header.Add("Accept", "text/html")
		response := r.Do(request)
		assert.Contains(t, response.Body, "<html")
		assert.Equal(t, 200, response.StatusCode)
	})
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

func TestMKCOL(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("MKCOL", "/_test", nil)
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		response = r.Post("/_test/abc", "text/turtle", "<a> <b> <c>.")
		assert.Equal(t, 200, response.StatusCode)

		request, _ = http.NewRequest("MKCOL", "/_test/abc", nil)
		response = r.Do(request)
		assert.Equal(t, 409, response.StatusCode)

		response = r.Post("/_test", "text/turtle", "<a> <b> <c>.")
		assert.Equal(t, 500, response.StatusCode)

		request, _ = http.NewRequest("GET", "/_test", nil)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestLDPPostLDPC(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("POST", "/_test/", strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/ldpc>."))
		request.Header.Add("Content-Type", "text/turtle")
		request.Header.Add("Slug", "ldpc")
		request.Header.Add("Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)
		newLDPC := response.RawResponse.Header.Get("Location")
		assert.True(t, strings.HasSuffix(newLDPC, "/"))

		metaURI := ParseLinkHeader(response.RawResponse.Header.Get("Link")).MatchRel("meta")
		assert.Equal(t, newLDPC+".meta", metaURI)

		request, _ = http.NewRequest("GET", newLDPC, nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)

		request, _ = http.NewRequest("GET", metaURI, nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, response.RawResponse.Header.Get("Triples"), "1")

		response = r.Delete(metaURI, "", "")
		assert.Equal(t, 200, response.StatusCode)

		response = r.Delete(newLDPC, "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestLDPPostLDPRWithSlug(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("POST", "/_test/", strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/two>."))
		request.Header.Add("Content-Type", "text/turtle")
		request.Header.Add("Slug", "ldpr")
		request.Header.Add("Link", "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"")
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)
		newLDPR := response.RawResponse.Header.Get("Location")

		request, _ = http.NewRequest("GET", newLDPR, nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.RawResponse.Header.Get("Triples"), "1")
		assert.Equal(t, response.Body, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<>\n    a <http://example.org/two> .\n\n")

		response = r.Delete(newLDPR, "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestLDPPostLDPRNoSlug(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("POST", "/_test/", strings.NewReader("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/two>."))
		request.Header.Add("Content-Type", "text/turtle")
		request.Header.Add("Link", "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"")
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)
		newLDPR := response.RawResponse.Header.Get("Location")

		request, _ = http.NewRequest("GET", newLDPR, nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, 6, len(filepath.Base(newLDPR)))
		assert.Equal(t, "1", response.RawResponse.Header.Get("Triples"))
		assert.Equal(t, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<>\n    a <http://example.org/two> .\n\n", response.Body)
		response = r.Delete(newLDPR, "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestLDPGetLDPC(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "text/turtle")
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)

		g := NewGraph("/_test/")
		g.Parse(strings.NewReader(response.Body), "text/turtle")
		assert.NotNil(t, g.One(rdf.NewResource("/_test/"), rdf.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), rdf.NewResource("http://www.w3.org/ns/ldp#BasicContainer")))
	})
}

func TestLDPPreferContainmentHeader(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("Prefer", "return=representation; omit=\"http://www.w3.org/ns/ldp#PreferEmptyContainer\"")
		response := r.Do(request)

		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "return=representation", response.RawResponse.Header.Get("Preference-Applied"))
		g := NewGraph("/_test/")
		g.Parse(strings.NewReader(response.Body), "text/turtle")
		assert.NotNil(t, g.One(rdf.NewResource("/_test/"), rdf.NewResource("http://www.w3.org/ns/ldp#contains"), nil))

		request, _ = http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("Prefer", "return=representation; include=\"http://www.w3.org/ns/ldp#PreferEmptyContainer\", return=representation; omit=\"http://www.w3.org/ns/ldp#PreferContainment\"")
		response = r.Do(request)

		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "return=representation", response.RawResponse.Header.Get("Preference-Applied"))
		g = NewGraph("/_test/")
		g.Parse(strings.NewReader(response.Body), "text/turtle")
		assert.Nil(t, g.One(rdf.NewResource("/_test/"), rdf.NewResource("http://www.w3.org/ns/ldp#contains"), nil))
	})
}

func TestLDPPreferEmptyHeader(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("Prefer", "return=representation; omit=\"http://www.w3.org/ns/ldp#PreferEmptyContainer\"")
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "return=representation", response.RawResponse.Header.Get("Preference-Applied"))

		g := NewGraph("/_test/")
		g.Parse(strings.NewReader(response.Body), "text/turtle")
		assert.NotNil(t, g.One(rdf.NewResource("/_test/abc"), nil, nil))

		request, _ = http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "text/turtle")
		request.Header.Add("Prefer", "return=representation; include=\"http://www.w3.org/ns/ldp#PreferEmptyContainer\"")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "return=representation", response.RawResponse.Header.Get("Preference-Applied"))

		g = NewGraph("/_test/")
		g.Parse(strings.NewReader(response.Body), "text/turtle")
		assert.Nil(t, g.One(rdf.NewResource("/_test/abc"), nil, nil))
	})
}

func TestStreaming(t *testing.T) {
	Streaming = true
	defer func() {
		Streaming = false
	}()
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Get("/_test/abc")
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.Body, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c> .\n\n")

		request, _ := http.NewRequest("PUT", "/_test/abc", nil)
		response = r.Do(request)
		assert.Equal(t, 201, response.StatusCode)
	})
}

func TestETag(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		etag := "3520a395fdacd680ba71627e3ef6b13a"
		response := r.Get("/_test/")
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, etag, response.RawResponse.Header.Get("ETag"))

		etag = "d41d8cd98f00b204e9800998ecf8427e"
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
		assert.Equal(t, response.RawResponse.Header.Get("Triples"), "2")

		request, _ = http.NewRequest("POST", "/_test/abc", strings.NewReader("DELETE DATA { <a> <b> <c> . }"))
		request.Header.Add("Content-Type", "application/sparql-update")
		response = r.Do(request)
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.RawResponse.Header.Get("Triples"), "1")
	})
}

func TestPOSTTurtle(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Post("/_test/abc", "text/turtle", "<a> <b> <c1> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.RawResponse.Header.Get("Triples"), "2")

		response = r.Post("/_test/abc", "text/turtle", "<a> <b> <c2> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.RawResponse.Header.Get("Triples"), "3")

		request, _ := http.NewRequest("GET", "/_test/abc", nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.RawResponse.Header.Get("Triples"), "3")
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
		response := r.Put("/_test/abc", "text/turtle", "<d> <e> <f> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 201, response.StatusCode)

		request, _ := http.NewRequest("GET", "/_test/abc", nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.Body, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<d>\n    <e> <f> .\n\n")
	})
}

func TestPUTMultiForm(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		path := "./tests/img.jpg"
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

		request, _ := http.NewRequest("PUT", "", bodyReader)
		request.Header.Add("Content-Type", "multipart/form-data; boundary="+multiWriter.Boundary())
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		response = r.Delete("/img.jpg", "", "")
		assert.Equal(t, 200, response.StatusCode)

		response = r.Get("/img.jpg")
		assert.Equal(t, 404, response.StatusCode)
	})
}

func TestLISTDIR(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("MKCOL", "/_test/dir", nil)
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)

		response = r.Post("/_test/abc", "text/turtle", "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/abc> .")
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)

		request, _ = http.NewRequest("GET", "/_test/", nil)
		request.Header.Add("Accept", "text/turtle")
		response = r.Do(request)

		assert.Equal(t, 200, response.StatusCode)

		rdfs := rdf.NewNamespace("http://www.w3.org/1999/02/22-rdf-syntax-ns#")
		posix := rdf.NewNamespace("http://www.w3.org/ns/posix/stat#")

		g := NewGraph("/_test/")
		g.Parse(strings.NewReader(response.Body), "text/turtle")

		f := rdf.NewResource("/_test/abc")
		assert.Equal(t, g.One(f, rdfs.Get("type"), rdf.NewResource("http://example.org/abc")).Object, rdf.NewResource("http://example.org/abc"))
		assert.Equal(t, g.One(f, rdfs.Get("type"), posix.Get("File")).Object, posix.Get("File"))
		assert.NotNil(t, g.One(f, posix.Get("size"), nil))
		assert.NotNil(t, g.One(f, posix.Get("mtime"), nil))

		d := rdf.NewResource("/_test/dir/")
		assert.Equal(t, g.One(d, rdfs.Get("type"), posix.Get("Directory")).Object, posix.Get("Directory"))
		assert.NotNil(t, g.One(d, posix.Get("size"), nil))
		assert.NotNil(t, g.One(d, posix.Get("mtime"), nil))
	})
}

func TestGlob(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Post("/_test/1", "text/turtle", "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/one>;\n"+
			"    <http://example.org/b> <#c> .\n    <#c> a <http://example.org/e> .")
		assert.Equal(t, 200, response.StatusCode)

		response = r.Post("/_test/2", "text/turtle", "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<> a <http://example.org/two>.")
		assert.Equal(t, 200, response.StatusCode)

		request, _ := http.NewRequest("GET", "/_test/*", nil)
		response = r.Do(request)

		assert.Equal(t, 200, response.StatusCode)

		rdfs := rdf.NewNamespace("http://www.w3.org/1999/02/22-rdf-syntax-ns#")
		g := NewGraph("/_test/")
		g.Parse(strings.NewReader(response.Body), "text/turtle")

		assert.NotEmpty(t, g)
		assert.Equal(t, g.One(rdf.NewResource("/_test/1"), rdfs.Get("type"), rdf.NewResource("http://example.org/one")).Object, rdf.NewResource("http://example.org/one"))
		assert.Equal(t, g.One(rdf.NewResource("/_test/1#c"), rdfs.Get("type"), rdf.NewResource("http://example.org/e")).Object, rdf.NewResource("http://example.org/e"))
		assert.Equal(t, g.One(rdf.NewResource("/_test/2"), rdfs.Get("type"), rdf.NewResource("http://example.org/two")).Object, rdf.NewResource("http://example.org/two"))

		request, _ = http.NewRequest("DELETE", "/_test/1", nil)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)

		request, _ = http.NewRequest("DELETE", "/_test/2", nil)
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestHEAD(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("HEAD", "/_test/abc", nil)
		response := r.Do(request)
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.RawResponse.Header.Get("Triples"), "2")
	})
}

func TestDELETE(t *testing.T) {
	if !testDelete {
		return
	}
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Delete("/_test/abc", "", "")
		assert.Empty(t, response.Body)
		assert.Equal(t, 200, response.StatusCode)

		response = r.Get("/_test/abc")
		assert.Equal(t, 404, response.StatusCode)
	})
}

func TestDELETEFolder(t *testing.T) {
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
		assert.Empty(t, response.Body)
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
		response = r.Delete("/test.raw", "", "")
		assert.Equal(t, response.StatusCode, 200)
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
