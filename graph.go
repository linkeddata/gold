package gold

import (
	"encoding/json"
	rdf "github.com/kierdavis/argo"
	crdf "github.com/presbrey/goraptor"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

var (
	mimeParser      = map[string]string{}
	mimeSerializer  = map[string]string{}
	serializerMimes = []string{}

	httpClient = &http.Client{}
)

func init() {
	for _, syntax := range crdf.ParserSyntax {
		mimeParser[syntax.MimeType] = syntax.Name
	}
	mimeParser["text/n3"] = mimeParser["text/turtle"]
	mimeParser["application/json"] = "internal"
	mimeParser["application/sparql-update"] = "internal"

	for name, syntax := range crdf.SerializerSyntax {
		switch name {
		case "rdfxml-xmp", "rdfxml":
			continue
		}
		mimeSerializer[syntax.MimeType] = syntax.Name
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

func term2term(term crdf.Term) rdf.Term {
	switch term := term.(type) {
	case *crdf.Blank:
		return rdf.NewBlankNode(term.String())
	case *crdf.Literal:
		return rdf.NewLiteralWithLanguageAndDatatype(term.Value, term.Lang, rdf.NewResource(term.Datatype))
	case *crdf.Uri:
		return rdf.NewResource(term.String())
	}
	return nil
}

func (g *Graph) AddStatement(st *crdf.Statement) {
	s, p, o := term2term(st.Subject), term2term(st.Predicate), term2term(st.Object)
	for triple := range g.Filter(s, p, nil) {
		if triple.Object.Equal(o) {
			return
		}
	}
	g.AddTriple(s, p, o)
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
		g.Parse(r.Body, r.Header.Get("Content-Type"))
	}
	return
}

func (g *Graph) Parse(reader io.Reader, mime string) {
	parserName := mimeParser[mime]
	if len(parserName) == 0 {
		parserName = "guess"
	}
	parser := crdf.NewParser(parserName)
	defer parser.Free()
	out := parser.Parse(reader, g.baseUri)
	for s := range out {
		g.AddStatement(s)
	}
}

func (g *Graph) ParseFile(filename string) {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return
	}
	parser := crdf.NewParser("turtle")
	defer parser.Free()
	out := parser.ParseFile(filename, g.baseUri)
	for s := range out {
		g.AddStatement(s)
	}
}

func term2C(t rdf.Term) crdf.Term {
	switch t := t.(type) {
	case *rdf.BlankNode:
		node := crdf.Blank(t.ID)
		return &node
	case *rdf.Resource:
		node := crdf.Uri(t.URI)
		return &node
	case *rdf.Literal:
		dt := ""
		if t.Datatype != nil {
			dt = t.Datatype.(*rdf.Resource).URI
		}
		node := crdf.Literal{
			Value:    t.Value,
			Datatype: dt,
			Lang:     t.Language,
		}
		return &node
	}
	return nil
}

func (g *Graph) Write(mime string) (string, error) {
	serializerName := mimeSerializer[mime]
	if len(serializerName) == 0 {
		serializerName = "turtle"
	}
	serializer := crdf.NewSerializer(serializerName)
	defer serializer.Free()

	ch := make(chan *crdf.Statement, 1024)
	go func() {
		for triple := range g.IterTriples() {
			ch <- &crdf.Statement{
				Subject:   term2C(triple.Subject),
				Predicate: term2C(triple.Predicate),
				Object:    term2C(triple.Object),
			}
		}
		close(ch)
	}()
	return serializer.Serialize(ch, g.baseUri)
}

func (g *Graph) WriteFile(file *os.File, mime string) error {
	serializerName := mimeSerializer[mime]
	if len(serializerName) == 0 {
		serializerName = "turtle"
	}
	serializer := crdf.NewSerializer(serializerName)
	defer serializer.Free()
	err := serializer.SetFile(file, g.baseUri)
	if err != nil {
		return err
	}
	ch := make(chan *crdf.Statement, 1024)
	go func() {
		for triple := range g.IterTriples() {
			ch <- &crdf.Statement{
				Subject:   term2C(triple.Subject),
				Predicate: term2C(triple.Predicate),
				Object:    term2C(triple.Object),
			}
		}
		close(ch)
	}()
	serializer.AddN(ch)
	return nil
}

type jsonPatch map[string]map[string][]struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

func (g *Graph) JSONPatch(r io.Reader) error {
	v := make(jsonPatch)
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	for s, sv := range v {
		for p, pv := range sv {
			subject := rdf.NewResource(s)
			predicate := rdf.NewResource(p)
			for triple := range g.Filter(subject, predicate, nil) {
				g.Remove(triple)
			}
			for _, o := range pv {
				switch o.Type {
				case "uri":
					g.AddTriple(subject, predicate, rdf.NewResource(o.Value))
				case "literal":
					g.AddTriple(subject, predicate, rdf.NewLiteral(o.Value))
				}
			}
		}
	}
	return nil
}
