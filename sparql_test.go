package gold

import (
	"strings"
	"testing"
)

func TestSPARQLInsert(t *testing.T) {
	sparql := NewSPARQL("https://test/")
	sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> <c> . }"))
	if len(sparql.queries) != 1 {
		t.Errorf("got %d queries, expected 1\n", len(sparql.queries))
	}
	if sparql.queries[0].verb != "INSERT DATA" {
		t.Errorf("got %s, expected INSERT DATA\n", sparql.queries[0].verb)
	}
	if sparql.queries[0].body != "<a> <b> <c> ." {
		t.Errorf("got %s, expected <a> <b> <c> .\n", sparql.queries[0].body)
	}
}

func TestSPARQLInsertDelete(t *testing.T) {
	sparql := NewSPARQL("https://test/")
	sparql.Parse(strings.NewReader("INSERT DATA { <a> <b> <c> . }; DELETE DATA { <a> <b> <c> . }"))
	if len(sparql.queries) != 2 {
		t.Errorf("got %d queries, expected 2\n", len(sparql.queries))
	}
	if sparql.queries[0].verb != "INSERT DATA" {
		t.Errorf("got %s, expected INSERT DATA\n", sparql.queries[0].verb)
	}
	if sparql.queries[0].body != "<a> <b> <c> ." {
		t.Errorf("got %s, expected <a> <b> <c> .\n", sparql.queries[0].body)
	}
	if sparql.queries[1].verb != "DELETE DATA" {
		t.Errorf("got %s, expected DELETE DATA\n", sparql.queries[0].verb)
	}
	if sparql.queries[1].body != "<a> <b> <c> ." {
		t.Errorf("got %s, expected <a> <b> <c> .\n", sparql.queries[0].body)
	}
}
