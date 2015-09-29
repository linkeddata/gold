package gold

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSPARQLParseInsert(t *testing.T) {
	sparql := NewSPARQLUpdate("https://test/")
	sparql.Parse(strings.NewReader("INSERT { <a> <b> <c> . }"))
	assert.Equal(t, len(sparql.queries), 1)
	if len(sparql.queries) > 0 {
		assert.Equal(t, sparql.queries[0].verb, "INSERT")
		assert.Equal(t, sparql.queries[0].body, " <a> <b> <c> . ")
	}

	sparql = NewSPARQLUpdate("https://test/")
	sparql.Parse(strings.NewReader("INSERT { <a> <b> <data:image/jpeg;base64,/9j/4AAQSkZ=> . }"))
	assert.Equal(t, len(sparql.queries), 1)
	if len(sparql.queries) > 0 {
		assert.Equal(t, sparql.queries[0].verb, "INSERT")
		assert.Equal(t, sparql.queries[0].body, " <a> <b> <data:image/jpeg;base64,/9j/4AAQSkZ=> . ")
	}
}

func TestSPARQLParseInsertDeleteUri(t *testing.T) {
	sparql := NewSPARQLUpdate("https://test/")
	sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> <c> . }; DELETE DATA { <a> <b> <c> . }"))
	assert.Equal(t, len(sparql.queries), 2)
	if len(sparql.queries) > 1 {
		assert.Equal(t, sparql.queries[0].verb, "INSERT DATA")
		assert.Equal(t, sparql.queries[0].body, " <a> <b> <c> . ")
		assert.Equal(t, sparql.queries[1].verb, "DELETE DATA")
		assert.Equal(t, sparql.queries[1].body, " <a> <b> <c> . ")
	}
}

func TestSPARQLParseInsertDeleteLiteral(t *testing.T) {
	sparql := NewSPARQLUpdate("https://test/")
	sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> \"};{\" . }; DELETE DATA { <a> <b> \"};{\" . }"))
	assert.Equal(t, len(sparql.queries), 2)
	if len(sparql.queries) > 1 {
		assert.Equal(t, sparql.queries[0].verb, "INSERT DATA")
		assert.Equal(t, sparql.queries[0].body, " <a> <b> \"};{\" . ")
		assert.Equal(t, sparql.queries[1].verb, "DELETE DATA")
		assert.Equal(t, sparql.queries[1].body, " <a> <b> \"};{\" . ")
	}
}

func TestSPARQLInsertLiteralWithDataType(t *testing.T) {
	sparql := NewSPARQLUpdate("https://test/")
	err := sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> \"123\"^^<http://www.w3.org/2001/XMLSchema#int> . }"))
	assert.NoError(t, err)
	assert.Equal(t, len(sparql.queries), 1)
	assert.Equal(t, "INSERT DATA", sparql.queries[0].verb)
	assert.Equal(t, " <a> <b> \"123\"^^<http://www.w3.org/2001/XMLSchema#int> . ", sparql.queries[0].body)
	graph := NewGraph("https://test/")
	code, err := graph.SPARQLUpdate(sparql)
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 1, graph.Len())
}

func TestSPARQLUpdateBnodePresent(t *testing.T) {
	graph := NewGraph("https://test/")
	sparql := NewSPARQLUpdate("https://test/")
	err := sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> [ <c> <d> ] . }"))
	assert.NoError(t, err)
	code, err := graph.SPARQLUpdate(sparql)
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 2, graph.Len())

	err = sparql.Parse(strings.NewReader("DELETE DATA { <a> <b> [ <c> <d> ] . }"))
	assert.NoError(t, err)
	code, err = graph.SPARQLUpdate(sparql)
	assert.Equal(t, 500, code)
	assert.Error(t, err)
}

func TestSPARQLUpdateTripleNotPresent(t *testing.T) {
	graph := NewGraph("https://test/")
	sparql := NewSPARQLUpdate("https://test/")
	err := sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> <c> . }"))
	assert.NoError(t, err)
	code, err := graph.SPARQLUpdate(sparql)
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 1, graph.Len())

	err = sparql.Parse(strings.NewReader("DELETE DATA { <a> <b> <d> . }"))
	assert.NoError(t, err)
	code, err = graph.SPARQLUpdate(sparql)
	assert.Equal(t, 409, code)
	assert.Error(t, err)
}

func TestSPARQLUpdateMultipleTriples(t *testing.T) {
	graph := NewGraph("https://test/")
	sparql := NewSPARQLUpdate("https://test/")
	err := sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> <c> . }; INSERT DATA { <a> <b> <d> . }"))
	assert.NoError(t, err)
	code, err := graph.SPARQLUpdate(sparql)
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 2, graph.Len())

	sparql = NewSPARQLUpdate("https://test/")
	err = sparql.Parse(strings.NewReader("DELETE DATA { <a> <b> <c> . }; DELETE DATA { <a> <b> <d> . }; INSERT DATA { <a> <b> <f> . }"))
	assert.NoError(t, err)
	code, err = graph.SPARQLUpdate(sparql)
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 1, graph.Len())
}
