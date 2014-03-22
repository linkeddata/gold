package gold

import (
	"bytes"
	"io"
	"io/ioutil"
	"strings"
	"text/scanner"
)

type SPARQLQuery struct {
	verb string
	body string

	graph AnyGraph
}

type SPARQL struct {
	baseUri string
	queries []SPARQLQuery
}

func NewSPARQL(baseUri string) *SPARQL {
	return &SPARQL{
		baseUri: baseUri,
		queries: []SPARQLQuery{},
	}
}

func (sparql *SPARQL) Parse(src io.Reader) error {
	b, _ := ioutil.ReadAll(src)
	s := new(scanner.Scanner).Init(bytes.NewReader(b))
	s.Mode = scanner.ScanIdents | scanner.ScanStrings

	start := 0
	level := 0
	verb := ""
	tok := s.Scan()
	for tok != scanner.EOF {
		switch tok {
		case -2:
			if level == 0 {
				if len(verb) > 0 {
					verb += " "
				}
				verb += s.TokenText()
			}

		case 123: // {
			if level == 0 {
				start = s.Position.Offset
			}
			level += 1

		case 125: // }
			level -= 1
			if level == 0 {
				query := SPARQLQuery{
					body:  string(b[start+1 : s.Position.Offset]),
					graph: NewGraph(sparql.baseUri),
					verb:  verb,
				}
				query.graph.Parse(strings.NewReader(query.body), "text/turtle")
				sparql.queries = append(sparql.queries, query)
			}

		case 59: // ;
			verb = ""
		}

		tok = s.Scan()
	}

	return nil
}

func (g *Graph) SPARQLUpdate(sparql *SPARQL) {
	for _, query := range sparql.queries {
		switch query.verb {
		case "INSERT", "INSERT DATA":
			for triple := range query.graph.IterTriples() {
				g.Add(triple)
			}
		case "DELETE", "DELETE DATA":
			for pattern := range query.graph.IterTriples() {
				for triple := range g.Filter(pattern.Subject, pattern.Predicate, nil) {
					if pattern.Object.Equal(triple.Object) {
						g.Remove(triple)
					}
				}
			}
		}
	}
}
