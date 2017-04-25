package gold

import (
	"strings"
)

var (
	ns = struct {
		rdf, rdfs, acl, cert, foaf, stat, ldp, dct, space, st NS
	}{
		rdf:   NewNS("http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
		rdfs:  NewNS("http://www.w3.org/2000/01/rdf-schema#"),
		acl:   NewNS("http://www.w3.org/ns/auth/acl#"),
		cert:  NewNS("http://www.w3.org/ns/auth/cert#"),
		foaf:  NewNS("http://xmlns.com/foaf/0.1/"),
		stat:  NewNS("http://www.w3.org/ns/posix/stat#"),
		ldp:   NewNS("http://www.w3.org/ns/ldp#"),
		dct:   NewNS("http://purl.org/dc/terms/"),
		space: NewNS("http://www.w3.org/ns/pim/space#"),
		st:    NewNS("http://www.w3.org/ns/solid/terms#"),
	}
)

// NS is a generic namespace type
type NS string

// NewNS is used to set a new namespace
func NewNS(base string) (ns NS) {
	return NS(base)
}

// Get is used to return the prefix for a namespace
func (ns NS) Get(name string) (term Term) {
	return NewResource(string(ns) + name)
}

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

func defrag(s string) string {
	lst := strings.Split(s, "#")
	if len(lst) != 2 {
		return s
	}
	return lst[0]
}

func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] != '"' {
		return s
	}
	if s[len(s)-1] != '"' {
		return s
	}
	return s[1 : len(s)-1]
}

// frag = lambda x: x[x.find('#')==-1 and len(x) or x.find('#'):len(x)-(x[-1]=='>')]
// unfrag = lambda x: '#' in x and (x[:x.find('#')==-1 and len(x) or x.find('#')] + (x[0]=='<' and '>' or '')) or x
// cpfrag = lambda x,y: unfrag(y)[-1] == '>' and unfrag(y)[:-1]+frag(x)+'>' or unfrag(y)+frag(x)
