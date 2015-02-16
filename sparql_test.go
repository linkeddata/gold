package gold

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSPARQLBasic(t *testing.T) {
	sparql := NewSPARQL("http://www.w3.org/")
	sparql.Load("http://www.w3.org/ns/auth/acl")
	sparql.Parse("SELECT * WHERE { ?s ?p ?o }")
	sparql.Execute()

	data := sparql.Results()
	v := SPARQLResults{}
	err := json.Unmarshal(data, &v)
	assert.NoError(t, err)

	assert.Len(t, v.Head.Vars, 3)
	assert.True(t, len(v.Results.Bindings) > 50)
}
