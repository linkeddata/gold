package gold

import (
	"strings"
	"testing"

	jsonld "github.com/linkeddata/gojsonld"
	"github.com/stretchr/testify/assert"
)

func TestJSONTerm2Term(t *testing.T) {
	term := jsonld.NewResource("http://test.org/")
	res1 := jterm2term(term)
	res2 := NewResource("http://test.org/")
	assert.True(t, res2.Equal(res1))

	term = jsonld.NewLiteralWithDatatype("text", jsonld.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))
	res1 = jterm2term(term)
	res2 = NewLiteralWithDatatype("text", NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))
	assert.True(t, res2.Equal(res1))
}

func TestParseJSONLD(t *testing.T) {
	r := strings.NewReader(`{ "@id": "http://greggkellogg.net/foaf#me", "http://xmlns.com/foaf/0.1/name": "Gregg Kellogg" }`)
	g := NewGraph("https://test.org/")
	g.Parse(r, "application/ld+json")
	assert.Equal(t, 1, g.Len())
}

func TestSerializeJSONLD(t *testing.T) {
	g := NewGraph("https://test.org/")
	g.AddTriple(NewResource("a"), NewResource("b"), NewResource("c"))
	assert.Equal(t, 1, g.Len())
	toJSON, _ := g.Serialize("application/ld+json")
	assert.Equal(t, `[{"@id":"a","b":[{"@id":"c"}]}]`, toJSON)
}

func TestGraphPatch(t *testing.T) {
	var (
		buf   string
		err   error
		graph = NewGraph("https://test/")
	)

	graph.JSONPatch(strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c"}]}}`))
	buf, err = graph.Serialize("text/turtle")
	assert.Nil(t, err)
	assert.Equal(t, buf, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c> .\n\n")

	graph.JSONPatch(strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c2"}]}}`))
	buf, err = graph.Serialize("text/turtle")
	assert.Nil(t, err)
	assert.Equal(t, buf, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c2> .\n\n")

	graph.JSONPatch(strings.NewReader(`{"a":{"b2":[{"type":"uri","value":"c2"}]}}`))
	buf, err = graph.Serialize("text/turtle")
	assert.Nil(t, err)
	assert.Equal(t, buf, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c2> ;\n    <b2> <c2> .\n\n")
}

func TestGraphOne(t *testing.T) {
	g := NewGraph("http://test/")

	g.AddTriple(NewResource("a"), NewResource("b"), NewResource("c"))
	assert.Equal(t, g.One(NewResource("a"), nil, nil).String(), "<a> <b> <c> .")
	assert.Equal(t, g.One(NewResource("a"), NewResource("b"), nil).String(), "<a> <b> <c> .")

	g.AddTriple(NewResource("a"), NewResource("b"), NewResource("d"))
	assert.Equal(t, g.One(NewResource("a"), NewResource("b"), NewResource("d")).String(), "<a> <b> <d> .")
	assert.Equal(t, g.One(nil, NewResource("b"), NewResource("d")).String(), "<a> <b> <d> .")

	g.AddTriple(NewResource("g"), NewResource("b2"), NewLiteral("e"))
	assert.Equal(t, g.One(nil, NewResource("b2"), nil).String(), "<g> <b2> \"e\" .")
	assert.Equal(t, g.One(nil, nil, NewLiteral("e")).String(), "<g> <b2> \"e\" .")

	assert.Nil(t, g.One(NewResource("x"), nil, nil))
	assert.Nil(t, g.One(nil, NewResource("x"), nil))
	assert.Nil(t, g.One(nil, nil, NewResource("x")))
}

func TestGraphAll(t *testing.T) {
	g := NewGraph("http://test/")
	g.AddTriple(NewResource("a"), NewResource("b"), NewResource("c"))
	g.AddTriple(NewResource("a"), NewResource("b"), NewResource("d"))
	g.AddTriple(NewResource("a"), NewResource("f"), NewLiteral("h"))
	g.AddTriple(NewResource("g"), NewResource("b2"), NewResource("e"))
	g.AddTriple(NewResource("g"), NewResource("b2"), NewResource("c"))

	assert.Equal(t, 0, len(g.All(nil, nil, nil)))
	assert.Equal(t, 3, len(g.All(NewResource("a"), nil, nil)))
	assert.Equal(t, 2, len(g.All(nil, NewResource("b"), nil)))
	assert.Equal(t, 1, len(g.All(nil, nil, NewResource("d"))))
	assert.Equal(t, 2, len(g.All(nil, nil, NewResource("c"))))
}
