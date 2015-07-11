package gold

import (
	crdf "github.com/presbrey/goraptor"
	"mime"
)

var mimeParser = map[string]string{
	"application/ld+json":       "jsonld",
	"application/json":          "internal",
	"application/sparql-update": "internal",
}

var mimeSerializer = map[string]string{
	"application/ld+json": "internal",
	"text/html":           "internal",
}

var mimeRdfExt = map[string]string{
	".ttl":    "text/turtle",
	".n3":     "text/n3",
	".rdf":    "application/rdf+xml",
	".jsonld": "application/ld+json",
}

var (
	serializerMimes = []string{}
)

func init() {
	// add missing extensions
	for k, v := range mimeRdfExt {
		mime.AddExtensionType(k, v)
	}

	for _, syntax := range crdf.ParserSyntax {
		switch syntax.MimeType {
		case "", "text/html":
			continue
		}
		mimeParser[syntax.MimeType] = syntax.Name
	}
	mimeParser["text/n3"] = mimeParser["text/turtle"]

	for name, syntax := range crdf.SerializerSyntax {
		switch name {
		case "json-triples":
			// only activate: json
			continue
		case "rdfxml-xmp", "rdfxml":
			// only activate: rdfxml-abbrev
			continue
		}
		mimeSerializer[syntax.MimeType] = syntax.Name
	}

	for mime := range mimeSerializer {
		switch mime {
		case "application/xhtml+xml":
			continue
		}
		serializerMimes = append(serializerMimes, mime)
	}
}
