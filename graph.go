package gold

import (
	rdf "github.com/kierdavis/argo"
	"github.com/presbrey/goraptor"
	"net/http"
)

var (
	parser     = map[string]*goraptor.Parser{}
	parserMime = map[string]string{}

	serializer      = map[string]*goraptor.Serializer{}
	serializerMime  = map[string]string{}
	serializerMimes = []string{}

	httpClient = &http.Client{}
)

func init() {
	for _, syntax := range goraptor.ParserSyntax {
		parser[syntax.Name] = goraptor.NewParser(syntax.Name)
		parserMime[syntax.MimeType] = syntax.Name
	}
	parser[""] = parser["guess"]
	parserMime["text/n3"] = parserMime["text/turtle"]

	for name, syntax := range goraptor.SerializerSyntax {
		switch name {
		case "rdfxml-xmp", "rdfxml":
			continue
		}
		serializer[syntax.Name] = goraptor.NewSerializer(syntax.Name)
		serializerMime[syntax.MimeType] = syntax.Name
		serializerMimes = append(serializerMimes, syntax.MimeType)
	}
	serializerMimes = append(serializerMimes, "text/html")
}

type Graph struct {
	*rdf.Graph

	baseTerm rdf.Term
	baseUri  string
}

func NewGraph(baseUri string) *Graph {
	return &Graph{
		Graph:    rdf.NewGraph(rdf.NewIndexStore()),
		baseTerm: rdf.NewResource(baseUri),
		baseUri:  baseUri,
	}
}

func (g *Graph) Term() rdf.Term {
	return g.baseTerm
}

func (g *Graph) URI() string {
	return g.baseUri
}

func term2term(term goraptor.Term) rdf.Term {
	switch term := term.(type) {
	case *goraptor.Blank:
		return rdf.NewBlankNode(term.String())
	case *goraptor.Literal:
		return rdf.NewLiteralWithLanguageAndDatatype(term.Value, term.Lang, rdf.NewResource(term.Datatype))
	case *goraptor.Uri:
		return rdf.NewResource(term.String())
	}
	return nil
}

func (g *Graph) AddStatement(st *goraptor.Statement) {
	g.AddTriple(term2term(st.Subject), term2term(st.Predicate), term2term(st.Object))
}

func (g *Graph) Load(uri string) (err error) {
	q, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return
	}
	q.Header.Set("Accept", "text/turtle,text/n3,application/rdf+xml")
	r, err := httpClient.Do(q)
	if err != nil {
		return
	}
	if r != nil {
		defer r.Body.Close()
		parser := goraptor.NewParser("guess")
		defer parser.Free()
		out := parser.Parse(r.Body, g.baseUri)
		for s := range out {
			g.AddStatement(s)
		}
	}
	return
}
