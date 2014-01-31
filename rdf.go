package gold

import (
	rdf "github.com/kierdavis/argo"
)

var (
	ns = map[string]rdf.Namespace{
		"rdf":  rdf.NewNamespace("http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
		"cert": rdf.NewNamespace("http://www.w3.org/ns/auth/cert#"),
	}
)
