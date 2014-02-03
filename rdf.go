package gold

import (
	rdf "github.com/kierdavis/argo"
)

var (
	ns = map[string]rdf.Namespace{
		"acl":  rdf.NewNamespace("http://www.w3.org/ns/auth/acl#"),
		"cert": rdf.NewNamespace("http://www.w3.org/ns/auth/cert#"),
		"rdf":  rdf.NewNamespace("http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
		"rdfs": rdf.NewNamespace("http://www.w3.org/2000/01/rdf-schema#"),
		"foaf": rdf.NewNamespace("http://xmlns.com/foaf/0.1/"),
	}
)
