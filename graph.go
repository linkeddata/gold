package gold

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	jsonld "github.com/linkeddata/gojsonld"
	crdf "github.com/presbrey/goraptor"
)

// AnyGraph defines methods common to Graph types
type AnyGraph interface {
	Len() int
	URI() string
	Parse(io.Reader, string)
	Serialize(string) (string, error)

	JSONPatch(io.Reader) error
	SPARQLUpdate(*SPARQLUpdate) (int, error)
	IterTriples() chan *Triple

	ReadFile(string)
	WriteFile(*os.File, string) error
}

var (
	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
)

// Graph structure
type Graph struct {
	triples map[*Triple]bool

	uri  string
	term Term
}

// NewGraph creates a Graph object
func NewGraph(uri string) *Graph {
	if uri[:5] != "http:" && uri[:6] != "https:" {
		panic(uri)
	}

	return &Graph{
		triples: make(map[*Triple]bool),
		uri:     uri,
		term:    NewResource(uri),
	}
}

// Len returns the length of the graph as number of triples in the graph
func (g *Graph) Len() int {
	return len(g.triples)
}

// Term returns a Graph Term object
func (g *Graph) Term() Term {
	return g.term
}

// URI returns a Graph URI object
func (g *Graph) URI() string {
	return g.uri
}

func term2term(term crdf.Term) Term {
	switch term := term.(type) {
	case *crdf.Blank:
		return NewBlankNode(term.String())
	case *crdf.Literal:
		if len(term.Datatype) > 0 {
			return NewLiteralWithLanguageAndDatatype(term.Value, term.Lang, NewResource(term.Datatype))
		}
		return NewLiteral(term.Value)
	case *crdf.Uri:
		return NewResource(term.String())
	}
	return nil
}

func jterm2term(term jsonld.Term) Term {
	switch term := term.(type) {
	case *jsonld.BlankNode:
		return NewBlankNode(term.RawValue())
	case *jsonld.Literal:
		if term.Datatype != nil && len(term.Datatype.String()) > 0 {
			return NewLiteralWithLanguageAndDatatype(term.Value, term.Language, NewResource(term.Datatype.RawValue()))
		}
		return NewLiteral(term.Value)
	case *jsonld.Resource:
		return NewResource(term.RawValue())
	}
	return nil
}

// One returns one triple based on a triple pattern of S, P, O objects
func (g *Graph) One(s Term, p Term, o Term) *Triple {
	for triple := range g.IterTriples() {
		if isNilOrEquals(s, triple.Subject) && isNilOrEquals(p, triple.Predicate) && isNilOrEquals(o, triple.Object) {
			return triple
		}
	}
	return nil
}

// IterTriples iterates through all the triples in a graph
func (g *Graph) IterTriples() (ch chan *Triple) {
	ch = make(chan *Triple)
	go func() {
		for triple := range g.triples {
			ch <- triple
		}
		close(ch)
	}()
	return ch
}

// Add is used to add a Triple object to the graph
func (g *Graph) Add(t *Triple) {
	g.triples[t] = true
}

// AddTriple is used to add a triple made of individual S, P, O objects
func (g *Graph) AddTriple(s Term, p Term, o Term) {
	g.triples[NewTriple(s, p, o)] = true
}

// Remove is used to remove a Triple object
func (g *Graph) Remove(t *Triple) {
	delete(g.triples, t)
}

// All is used to return all triples that match a given pattern of S, P, O objects
func (g *Graph) All(s Term, p Term, o Term) []*Triple {
	var triples []*Triple
	for triple := range g.IterTriples() {
		if s == nil && p == nil && o == nil {
			continue
		}

		if isNilOrEquals(s, triple.Subject) && isNilOrEquals(p, triple.Predicate) && isNilOrEquals(o, triple.Object) {
			triples = append(triples, triple)
		}
	}
	return triples
}

// AddStatement adds a Statement object
func (g *Graph) AddStatement(st *crdf.Statement) {
	g.AddTriple(term2term(st.Subject), term2term(st.Predicate), term2term(st.Object))
}

// Parse is used to parse RDF data from a reader, using the provided mime type
func (g *Graph) Parse(reader io.Reader, mime string) {
	parserName := mimeParser[mime]
	if len(parserName) == 0 {
		parserName = "guess"
	}

	if parserName == "jsonld" {
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(reader); err != nil {
			log.Println(err)
			return
		}

		jsonData, err := jsonld.ReadJSON(buf.Bytes())
		if err != nil {
			log.Println(err)
			return
		}

		options := &jsonld.Options{}
		options.Base = ""
		options.ProduceGeneralizedRdf = false
		dataSet, err := jsonld.ToRDF(jsonData, options)
		if err != nil {
			log.Println(err)
			return
		}

		for t := range dataSet.IterTriples() {
			g.AddTriple(jterm2term(t.Subject), jterm2term(t.Predicate), jterm2term(t.Object))
		}

		return
	}

	parser := crdf.NewParser(parserName)
	parser.SetLogHandler(func(level int, message string) {
		log.Println(message)
	})
	defer parser.Free()

	for s := range parser.Parse(reader, g.uri) {
		g.AddStatement(s)
	}
}

// ParseBase is used to parse RDF data from a reader, using the provided mime type and a base URI
func (g *Graph) ParseBase(reader io.Reader, mime string, baseURI string) {
	if len(baseURI) < 1 {
		baseURI = g.uri
	}
	parserName := mimeParser[mime]
	if len(parserName) == 0 {
		parserName = "guess"
	}
	parser := crdf.NewParser(parserName)
	defer parser.Free()
	out := parser.Parse(reader, baseURI)
	for s := range out {
		g.AddStatement(s)
	}
}

// ReadFile is used to read RDF data from a file into the graph
func (g *Graph) ReadFile(filename string) {
	stat, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return
	}
	if stat.IsDir() {
		return
	}
	if !stat.IsDir() && err != nil {
		log.Println(err)
		return
	}
	f, err := os.OpenFile(filename, os.O_RDONLY, 0)
	defer f.Close()
	if err != nil {
		log.Println(err)
		return
	}
	g.Parse(f, "text/turtle")
}

// AppendFile is used to append RDF from a file, using a base URI
func (g *Graph) AppendFile(filename string, baseURI string) {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return
	} else if err != nil {
		log.Println(err)
		return
	}
	f, err := os.OpenFile(filename, os.O_RDONLY, 0)
	defer f.Close()
	if err != nil {
		log.Println(err)
		return
	}
	g.ParseBase(f, "text/turtle", baseURI)
}

// LoadURI is used to load RDF data from a specific URI
func (g *Graph) LoadURI(uri string) (err error) {
	doc := defrag(uri)
	q, err := http.NewRequest("GET", doc, nil)
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
		if r.StatusCode == 200 {
			g.ParseBase(r.Body, r.Header.Get("Content-Type"), doc)
		} else {
			err = fmt.Errorf("Could not fetch graph from %s - HTTP %d", uri, r.StatusCode)
		}
	}
	return
}

func term2C(t Term) crdf.Term {
	switch t := t.(type) {
	case *BlankNode:
		node := crdf.Blank(t.ID)
		return &node
	case *Resource:
		node := crdf.Uri(t.URI)
		return &node
	case *Literal:
		dt := ""
		if t.Datatype != nil {
			dt = t.Datatype.(*Resource).URI
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

func (g *Graph) serializeJSONLd() ([]byte, error) {
	r := []map[string]interface{}{}
	for elt := range g.IterTriples() {
		one := map[string]interface{}{
			"@id": elt.Subject.(*Resource).URI,
		}
		switch t := elt.Object.(type) {
		case *Resource:
			one[elt.Predicate.(*Resource).URI] = []map[string]string{
				{
					"@id": t.URI,
				},
			}
			break
		case *Literal:
			v := map[string]string{
				"@value": t.Value,
			}
			if t.Datatype != nil && len(t.Datatype.String()) > 0 {
				v["@type"] = t.Datatype.String()
			}
			if len(t.Language) > 0 {
				v["@language"] = t.Language
			}
			one[elt.Predicate.(*Resource).URI] = []map[string]string{v}
		}
		r = append(r, one)
	}
	return json.Marshal(r)
}

// Serialize is used to serialize a graph based on a given mime type
func (g *Graph) Serialize(mime string) (string, error) {
	if mime == "application/ld+json" {
		b, err := g.serializeJSONLd()
		return string(b), err
	}

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
	return serializer.Serialize(ch, g.uri)
}

// WriteFile is used to dump RDF from a Graph into a file
func (g *Graph) WriteFile(file *os.File, mime string) error {
	serializerName := mimeSerializer[mime]
	if len(serializerName) == 0 {
		serializerName = "turtle"
	}
	serializer := crdf.NewSerializer(serializerName)
	defer serializer.Free()
	err := serializer.SetFile(file, g.uri)
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

// JSONPatch is used to perform a PATCH operation on a Graph using data from the reader
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
	base, _ := url.Parse(g.uri)
	for s, sv := range v {
		su, _ := base.Parse(s)
		for p, pv := range sv {
			pu, _ := base.Parse(p)
			subject := NewResource(su.String())
			predicate := NewResource(pu.String())
			for _, triple := range g.All(subject, predicate, nil) {
				g.Remove(triple)
			}
			for _, o := range pv {
				switch o.Type {
				case "uri":
					g.AddTriple(subject, predicate, NewResource(o.Value))
				case "literal":
					g.AddTriple(subject, predicate, NewLiteral(o.Value))
				}
			}
		}
	}
	return nil
}

// isNilOrEquals is a helper function returns true if first term is nil, otherwise checks equality
func isNilOrEquals(t1 Term, t2 Term) bool {
	if t1 == nil {
		return true
	}

	return t2.Equal(t1)
}
