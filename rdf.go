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

func brack(s string) string {
	if len(s) > 0 && s[0] == '<' {
		return s
	}
	if len(s) > 0 && s[len(s)-1] == '>' {
		return s
	}
	return "<" + s + ">"
}

func debrack(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] != '<' {
		return s
	}
	if s[len(s)-1] != '>' {
		return s
	}
	return s[1 : len(s)-1]
}

// frag = lambda x: x[x.find('#')==-1 and len(x) or x.find('#'):len(x)-(x[-1]=='>')]
// unfrag = lambda x: '#' in x and (x[:x.find('#')==-1 and len(x) or x.find('#')] + (x[0]=='<' and '>' or '')) or x
// cpfrag = lambda x,y: unfrag(y)[-1] == '>' and unfrag(y)[:-1]+frag(x)+'>' or unfrag(y)+frag(x)
