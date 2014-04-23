package gold

import (
	rdf "github.com/kierdavis/argo"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

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
	g.AddTriple(rdf.NewResource("a"), rdf.NewResource("b"), rdf.NewResource("c"))
	g.AddTriple(rdf.NewResource("a"), rdf.NewResource("b"), rdf.NewResource("d"))
	g.AddTriple(rdf.NewResource("a"), rdf.NewResource("f"), rdf.NewLiteral("h"))
	g.AddTriple(rdf.NewResource("g"), rdf.NewResource("b2"), rdf.NewResource("e"))

	assert.Equal(t, g.One(rdf.NewResource("a"), nil, nil).String(), "<a> <b> <c> .")
	assert.Equal(t, g.One(rdf.NewResource("a"), rdf.NewResource("b"), nil).String(), "<a> <b> <c> .")
	assert.Equal(t, g.One(rdf.NewResource("a"), rdf.NewResource("b"), rdf.NewResource("d")).String(), "<a> <b> <d> .")

	assert.Equal(t, g.One(nil, rdf.NewResource("b"), rdf.NewResource("d")).String(), "<a> <b> <d> .")
	assert.Equal(t, g.One(nil, rdf.NewResource("b2"), nil).String(), "<g> <b2> <e> .")
	assert.Equal(t, g.One(nil, nil, rdf.NewResource("e")).String(), "<g> <b2> <e> .")

	assert.Nil(t, g.One(rdf.NewResource("x"), nil, nil))
	assert.Nil(t, g.One(nil, rdf.NewResource("x"), nil))
	assert.Nil(t, g.One(nil, nil, rdf.NewResource("x")))
}

func TestGraphAll(t *testing.T) {
	g := NewGraph("http://test/")
	g.AddTriple(rdf.NewResource("a"), rdf.NewResource("b"), rdf.NewResource("c"))
	g.AddTriple(rdf.NewResource("a"), rdf.NewResource("b"), rdf.NewResource("d"))
	g.AddTriple(rdf.NewResource("a"), rdf.NewResource("f"), rdf.NewLiteral("h"))
	g.AddTriple(rdf.NewResource("g"), rdf.NewResource("b2"), rdf.NewResource("e"))
	g.AddTriple(rdf.NewResource("g"), rdf.NewResource("b2"), rdf.NewResource("c"))

	assert.Equal(t, len(g.All(nil, nil, nil)), 0)
	assert.Equal(t, len(g.All(rdf.NewResource("a"), nil, nil)), 3)
	assert.Equal(t, len(g.All(nil, rdf.NewResource("b"), nil)), 2)
	assert.Equal(t, len(g.All(nil, nil, rdf.NewResource("d"))), 1)
	assert.Equal(t, len(g.All(nil, nil, rdf.NewResource("c"))), 2)
}
