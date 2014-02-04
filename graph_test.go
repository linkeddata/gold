package gold

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestPatch(t *testing.T) {
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
