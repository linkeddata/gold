package gold

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	mimeParserExpect = map[string]string{
		"application/json":          "internal",
		"application/sparql-update": "internal",

		"application/ld+json":   "jsonld",
		"application/n-triples": "ntriples",
		"application/rdf+xml":   "rdfxml",
		"application/rss":       "rss-tag-soup",
		"application/x-trig":    "trig",
		"text/n3":               "turtle",
		"text/turtle":           "turtle",
		"text/x-nquads":         "nquads",
	}
	mimeSerializerExpect = map[string]string{
		"application/ld+json": "internal",
		"text/html":           "internal",

		"application/atom+xml":  "atom",
		"application/json":      "json",
		"application/n-triples": "ntriples",
		"application/rdf+xml":   "rdfxml-abbrev",
		"application/rss+xml":   "rss-1.0",
		"application/xhtml+xml": "html",
		"text/turtle":           "turtle",
		"text/x-graphviz":       "dot",
		"text/x-nquads":         "nquads",
	}
)

func TestMimeParserExpect(t *testing.T) {
	for k, v := range mimeParserExpect {
		assert.Equal(t, v, mimeParser[k])
	}
}

func TestMimeSerializerExpect(t *testing.T) {
	for k, v := range mimeSerializerExpect {
		assert.Equal(t, v, mimeSerializer[k])
	}
}
