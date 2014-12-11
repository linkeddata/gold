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

type AnyGraph interface {
	Len() int
	URI() string
	Parse(io.Reader, string)
	Serialize(string) (string, error)

	JSONPatch(io.Reader) error
	SPARQLUpdate(*SPARQL)
	IterTriples() chan *Triple

	ReadFile(string)
	WriteFile(*os.File, string) error
}

var (
	mimeParser      = map[string]string{}
	mimeSerializer  = map[string]string{}
	serializerMimes = []string{}

	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
)

func init() {
	for _, syntax := range crdf.ParserSyntax {
		switch syntax.MimeType {
		case "", "text/html":
			continue
		}
		mimeParser[syntax.MimeType] = syntax.Name
	}
	mimeParser["text/n3"] = mimeParser["text/turtle"]
	mimeParser["application/json"] = "internal"
	mimeParser["application/sparql-update"] = "internal"
	mimeParser["application/ld+json"] = "jsonld"

	for name, syntax := range crdf.SerializerSyntax {
		switch name {
		case "rdfxml-xmp", "rdfxml":
			continue
		}
		mimeSerializer[syntax.MimeType] = syntax.Name
	}
	mimeSerializer["application/ld+json"] = "internal"
	mimeSerializer["text/html"] = "internal"
	for mime, _ := range mimeSerializer {
		serializerMimes = append(serializerMimes, mime)
	}
}

type Graph struct {
	triples map[*Triple]bool

	uri  string
	term Term
}

func NewGraph(uri string) *Graph {
	if uri[:5] != "http:" && uri[:6] != "https:" {
		panic(uri)
	}
	return &Graph{
		triples: make(map[*Triple]bool),

		uri:  uri,
		term: NewResource(uri),
	}
}

func (g *Graph) Len() int {
	return len(g.triples)
}

func (g *Graph) Term() Term {
	return g.term
}

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
		} else {
			return NewLiteral(term.Value)
		}
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
		if len(term.Datatype.String()) > 0 {
			return NewLiteralWithLanguageAndDatatype(term.Value, term.Language, NewResource(term.Datatype.RawValue()))
		} else {
			return NewLiteral(term.Value)
		}
	case *jsonld.Resource:
		return NewResource(term.RawValue())
	}
	return nil
}

func (g *Graph) One(s Term, p Term, o Term) *Triple {
	for triple := range g.IterTriples() {
		if s != nil {
			if p != nil {
				if o != nil {
					if triple.Subject.Equal(s) && triple.Predicate.Equal(p) && triple.Object.Equal(o) {
						return triple
					}
				} else {
					if triple.Subject.Equal(s) && triple.Predicate.Equal(p) {
						return triple
					}
				}
			} else {
				if triple.Subject.Equal(s) {
					return triple
				}
			}
		} else if p != nil {
			if o != nil {
				if triple.Predicate.Equal(p) && triple.Object.Equal(o) {
					return triple
				}
			} else {
				if triple.Predicate.Equal(p) {
					return triple
				}
			}
		} else if o != nil {
			if triple.Object.Equal(o) {
				return triple
			}
		} else {
			return triple
		}
	}
	return nil
}

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

func (g *Graph) Add(t *Triple) {
	g.triples[t] = true
}
func (g *Graph) AddTriple(s Term, p Term, o Term) {
	g.triples[NewTriple(s, p, o)] = true
}
func (g *Graph) Remove(t *Triple) {
	delete(g.triples, t)
}

func (g *Graph) All(s Term, p Term, o Term) []*Triple {
	var triples []*Triple
	for triple := range g.IterTriples() {
		if s != nil {
			if p != nil {
				if o != nil {
					if triple.Subject.Equal(s) && triple.Predicate.Equal(p) && triple.Object.Equal(o) {
						triples = append(triples, triple)
					}
				} else {
					if triple.Subject.Equal(s) && triple.Predicate.Equal(p) {
						triples = append(triples, triple)
					}
				}
			} else {
				if triple.Subject.Equal(s) {
					triples = append(triples, triple)
				}
			}
		} else if p != nil {
			if o != nil {
				if triple.Predicate.Equal(p) && triple.Object.Equal(o) {
					triples = append(triples, triple)
				}
			} else {
				if triple.Predicate.Equal(p) {
					triples = append(triples, triple)
				}
			}
		} else if o != nil {
			if triple.Object.Equal(o) {
				triples = append(triples, triple)
			}
		}
	}
	return triples
}

func (g *Graph) AddStatement(st *crdf.Statement) {
	s, p, o := term2term(st.Subject), term2term(st.Predicate), term2term(st.Object)
	for _ = range g.All(s, p, o) {
		return
	}
	g.AddTriple(s, p, o)
}

func (g *Graph) Parse(reader io.Reader, mime string) {
	parserName := mimeParser[mime]
	if len(parserName) == 0 {
		parserName = "guess"
	}
	if parserName == "jsonld" {
		buf := new(bytes.Buffer)
		buf.ReadFrom(reader)
		jsonData, err := jsonld.ReadJSON(buf.Bytes())
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

	} else {
		parser := crdf.NewParser(parserName)
		defer parser.Free()
		out := parser.Parse(reader, g.uri)
		for s := range out {
			g.AddStatement(s)
		}
	}
}

func (g *Graph) ParseBase(reader io.Reader, mime string, baseUri string) {
	if len(baseUri) < 1 {
		baseUri = g.uri
	}
	parserName := mimeParser[mime]
	if len(parserName) == 0 {
		parserName = "guess"
	}
	parser := crdf.NewParser(parserName)
	defer parser.Free()
	out := parser.Parse(reader, baseUri)
	for s := range out {
		g.AddStatement(s)
	}
}

func (g *Graph) ReadFile(filename string) {
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
	g.Parse(f, "text/turtle")
}

func (g *Graph) AppendFile(filename string, baseUri string) {
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
	g.ParseBase(f, "text/turtle", baseUri)
}

func (g *Graph) LoadURI(uri string) (err error) {
	doc := defrag(uri)
	q, err := http.NewRequest("GET", doc, nil)
	if err != nil {
		return
	}
	q.Header.Set("Accept", "text/turtle,text/n3,application/rdf+xml")
	r, err := httpClient.Do(q)
	if err != nil {
		DebugLog("Graph", "LoadURI httpClient error: "+err.Error())
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

func (g *Graph) serializeJsonLd() ([]byte, error) {
	r := []map[string]interface{}{}
	for elt := range g.IterTriples() {
		one := map[string]interface{}{
			"@id": elt.Subject.(*Resource).URI,
		}
		switch t := elt.Object.(type) {
		case *Resource:
			one[elt.Predicate.(*Resource).URI] = []map[string]string{
				map[string]string{
					"@id": t.URI,
				},
			}
			break
		case *Literal:
			v := map[string]string{
				"@value": t.Value,
			}
			if len(t.Datatype.String()) > 0 {
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

func (g *Graph) Serialize(mime string) (string, error) {
	if mime == "application/ld+json" {
		b, err := g.serializeJsonLd()
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
