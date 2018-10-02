package gold

import (
	"errors"
	"fmt"
	"mime"
	"path/filepath"

	"github.com/gabriel-vasile/mimetype"
	crdf "github.com/presbrey/goraptor"

	"regexp"
	"sync"
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

var rdfExtensions = []string{
	".ttl",
	".n3",
	".rdf",
	".jsonld",
}

var (
	serializerMimes = []string{}
	validMimeType   = regexp.MustCompile(`^\w+/\w+$`)
	mutex           = &sync.Mutex{}
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

func GuessMimeType(path string) (string, error) {
	mimeType := "text/plain"

	guessedType, _, err := mimetype.DetectFile(path)
	if err != nil {
		fmt.Printf("Unknown mimeType from file: %s ==> %s", path, err)
		return mimeType, err
	}

	if guessedType != "" && validMimeType.MatchString(guessedType) {
		mimeType = guessedType
	}

	return mimeType, nil
}

func LookupExt(ctype string) string {
	for k, v := range mimeRdfExt {
		if v == ctype {
			return k
		}
	}
	return ""
}

func LookUpCtype(ext string) string {
	return mimeRdfExt[ext]
}

func AddRDFExtension(ext string) {
	rdfExtensions = append(rdfExtensions, ext)
}

func IsRdfExtension(ext string) bool {
	for _, v := range rdfExtensions {
		if v == ext {
			return true
		}
	}
	return false
}

func MimeLookup(path string) (string, string, bool) {
	var mimeType string
	maybeRDF := false
	ext := filepath.Ext(path)
	if len(ext) > 0 {
		if IsRdfExtension(ext) {
			maybeRDF = true
			mimeType = LookUpCtype(ext)
		} else {
			mimeType = mime.TypeByExtension(ext)
			if len(mimeType) > 0 {
				if len(LookupExt(ext)) > 0 {
					maybeRDF = true
				}
			}
		}
	}
	return mimeType, ext, maybeRDF
}

// MapPathToExtension returns the path with the proper extension that matches the given content type,
// even if the resource (path) contains a different extension
// Only works with Go 1.5+
//@@TODO should switch to a more comprehensive list of mime-to-ext (instead of using go's internal list)
func MapPathToExtension(path string, ctype string) (string, error) {
	if len(path) == 0 {
		return "", errors.New("MapPathToExt -- missing path or ctype value")
	}
	if path[len(path)-1:] == "/" {
		return path, nil
	}

	fileCType, ext, _ := MimeLookup(path)
	if len(fileCType) > 0 {
		fileCType, _, _ = mime.ParseMediaType(fileCType)
		if len(ctype) > 0 {
			if fileCType != ctype {
				// append the extension corresponding to Content-Type header
				newExt, err := mime.ExtensionsByType(ctype)
				if err != nil {
					return "", err
				}
				if len(newExt) > 0 {
					ext = newExt[0]
				}
				path += "$" + ext
			}
		}
	} else {
		if len(ext) > 0 {
			if len(ctype) > 0 {
				newExt, err := mime.ExtensionsByType(ctype)
				if err != nil {
					return "", err
				}
				if len(newExt) > 0 {
					match := false
					for _, e := range newExt {
						if e == ext {
							match = true
							break
						}
					}
					if !match {
						// could not find matching extension
						if !IsRdfExtension(newExt[0]) {
							path += "$" + newExt[0]
						}
					}
				}
			}
		} else {
			// !fileCtype, !ext, ctype
			if len(ctype) > 0 {
				// maybe it's an RDF resource
				if ext = LookupExt(ctype); len(ext) > 0 {
					path += ext
				} else {
					newExt, err := mime.ExtensionsByType(ctype)
					if err != nil {
						return "", err
					}
					if len(newExt) > 0 {
						path += newExt[0]
					}
				}
			} else {
				return "", errors.New("Cannot infer mime type from from empty file")
			}
		}
	}

	return path, nil
}
