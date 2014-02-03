package gold

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestSPARQLInsert(t *testing.T) {
	sparql := NewSPARQL("https://test/")
	sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> <c> . }"))
	assert.Equal(t, len(sparql.queries), 1)
	assert.Equal(t, sparql.queries[0].verb, "INSERT DATA")
	assert.Equal(t, sparql.queries[0].body, "<a> <b> <c> .")
}

func TestSPARQLInsertDelete(t *testing.T) {
	sparql := NewSPARQL("https://test/")
	sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> <c> . }; DELETE DATA { <a> <b> <c> . }"))
	assert.Equal(t, len(sparql.queries), 2)
	assert.Equal(t, sparql.queries[0].verb, "INSERT DATA")
	assert.Equal(t, sparql.queries[0].body, "<a> <b> <c> .")
	assert.Equal(t, sparql.queries[1].verb, "DELETE DATA")
	assert.Equal(t, sparql.queries[1].body, "<a> <b> <c> .")
}
