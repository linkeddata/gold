package gold

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestJSONPatch(t *testing.T) {
	var (
		buf   string
		err   error
		graph = NewGraph("https://test/")
	)

	graph.JSONPatch(strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c"}]}}`))
	buf, err = graph.Write("application/n-triples")
	assert.Nil(t, err)
	assert.Equal(t, buf, "<a> <b> <c> .\n")

	graph.JSONPatch(strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c2"}]}}`))
	buf, err = graph.Write("application/n-triples")
	assert.Nil(t, err)
	assert.Equal(t, buf, "<a> <b> <c2> .\n")

	graph.JSONPatch(strings.NewReader(`{"a":{"b2":[{"type":"uri","value":"c2"}]}}`))
	buf, err = graph.Write("application/n-triples")
	assert.Nil(t, err)
	assert.Equal(t, buf, "<a> <b> <c2> .\n<a> <b2> <c2> .\n")
}
