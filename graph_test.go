package gold

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

	assert.Equal(t, len(g.All(nil, nil, nil)), 0)
	assert.Equal(t, len(g.All(NewResource("a"), nil, nil)), 3)
	assert.Equal(t, len(g.All(nil, NewResource("b"), nil)), 2)
	assert.Equal(t, len(g.All(nil, nil, NewResource("d"))), 1)
	assert.Equal(t, len(g.All(nil, nil, NewResource("c"))), 2)
}
