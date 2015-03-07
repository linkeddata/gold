package gold

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSPARQLInsert(t *testing.T) {
	sparql := NewSPARQLUpdate("https://test/")
	sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> <c> . }"))
	assert.Equal(t, len(sparql.queries), 1)
	if len(sparql.queries) > 0 {
		assert.Equal(t, sparql.queries[0].verb, "INSERT DATA")
		assert.Equal(t, sparql.queries[0].body, " <a> <b> <c> . ")
	}
}

func TestSPARQLInsertDeleteUri(t *testing.T) {
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

func TestSPARQLInsertDeleteLiteral(t *testing.T) {
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

func TestSPARQLInsertDeleteLiteralWithDataType(t *testing.T) {
	sparql := NewSPARQLUpdate("https://test/")
	err := sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> \"123\"^^<http://www.w3.org/2001/XMLSchema#int> . }; DELETE DATA { <a> <b> \"123\"^^<http://www.w3.org/2001/XMLSchema#int> . }"))
	assert.NoError(t, err)
	assert.Equal(t, len(sparql.queries), 2)
	if len(sparql.queries) > 1 {
		assert.Equal(t, "INSERT DATA", sparql.queries[0].verb)
		assert.Equal(t, " <a> <b> \"123\"^^<http://www.w3.org/2001/XMLSchema#int> . ", sparql.queries[0].body)
		assert.Equal(t, "DELETE DATA", sparql.queries[1].verb)
		assert.Equal(t, " <a> <b> \"123\"^^<http://www.w3.org/2001/XMLSchema#int> . ", sparql.queries[1].body)
	}
	graph := NewGraph("https://test/")
	graph.SPARQLUpdate(sparql)
	assert.Empty(t, graph.triples)
}
