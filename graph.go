package gold

import (
	"github.com/presbrey/goraptor"
)

var (
	parser     = map[string]*goraptor.Parser{}
	parserMime = map[string]string{}

	serializer      = map[string]*goraptor.Serializer{}
	serializerMime  = map[string]string{}
	serializerMimes = []string{}
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
	//log.Println(serializerMimes)
}

type Graph struct{}

func NewGraph() *Graph {
	return &Graph{}
}
