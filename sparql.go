package gold

import (
	"io"
	"io/ioutil"
	"strings"
)

type SPARQLQuery struct {
	verb string
	body string

	graph *Graph
}

type SPARQL struct {
	baseUri string
	queries []SPARQLQuery
}

func NewSPARQL(baseUri string) *SPARQL {
	return &SPARQL{baseUri: baseUri}
}

func (sparql *SPARQL) Parse(r io.Reader) error {
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	body := string(bytes)
	lst := []string{}

	angles := 0
	curlys := 0
	quotes := 0
	buf := ""
	for _, s := range strings.Split(body, ";") {
		buf += s
		angles += strings.Count(s, "<")
		angles -= strings.Count(s, ">")
		curlys += strings.Count(s, "{")
		curlys -= strings.Count(s, "}")
		quotes += strings.Count(s, "\"")
		if angles == 0 && curlys == 0 && quotes%2 == 0 {
			lst = append(lst, buf)
			buf = ""
		}
	}

	for _, s := range lst {
		b0 := strings.Index(s, "{")
		b1 := strings.Index(s, "}")
		query := SPARQLQuery{
			verb:  strings.TrimSpace(s[0:b0]),
			body:  strings.TrimSpace(s[b0+1 : b1]),
			graph: NewGraph(sparql.baseUri),
		}
		query.graph.Parse(strings.NewReader(query.body), "text/turtle")
		sparql.queries = append(sparql.queries, query)
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
			for triple := range query.graph.IterTriples() {
				g.Remove(triple)
			}
		}
	}
}
