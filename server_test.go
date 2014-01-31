package gold

import (
	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

var (
	handler = Handler{}
)

func TestTurtlePOST(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Post("/abc", "text/turtle", "<a> <b> <c1> .")
		assert.Equal(t, 200, response.StatusCode)
	})
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Post("/abc", "text/turtle", "<a> <b> <c2> .")
		assert.Equal(t, 200, response.StatusCode)
	})
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/abc", nil)
		request.Header.Add("Accept", "text/turtle")
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.Body, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c1>, <c2> .\n\n")
	})
}

func TestTurtlePUT(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Put("/abc", "text/turtle", "<d> <e> <f> .")
		assert.Equal(t, 201, response.StatusCode)
	})
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/abc", nil)
		request.Header.Add("Accept", "text/turtle")
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, response.Body, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<d>\n    <e> <f> .\n\n")
	})
}

func TestMKCOL(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("MKCOL", "/_folder", nil)
		response := r.Do(request)
		assert.Equal(t, 201, response.StatusCode)
	})
	testflight.WithServer(handler, func(r *testflight.Requester) {
		request, _ := http.NewRequest("GET", "/_folder", nil)
		response := r.Do(request)
		assert.Equal(t, 501, response.StatusCode)
	})
}

func TestDELETE(t *testing.T) {
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Delete("/abc", "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Get("/abc")
		assert.Equal(t, 404, response.StatusCode)
	})
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Delete("/_folder", "", "")
		assert.Equal(t, 200, response.StatusCode)
	})
	testflight.WithServer(handler, func(r *testflight.Requester) {
		response := r.Get("/_folder")
		assert.Equal(t, 404, response.StatusCode)
	})
}
