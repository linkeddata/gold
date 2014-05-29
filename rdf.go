package gold

import (
	"strings"
)

var (
	ns = struct {
		rdf, rdfs, acl, cert, foaf, stat NS
	}{
		rdf:  NewNS("http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
		rdfs: NewNS("http://www.w3.org/2000/01/rdf-schema#"),
		acl:  NewNS("http://www.w3.org/ns/auth/acl#"),
		cert: NewNS("http://www.w3.org/ns/auth/cert#"),
		foaf: NewNS("http://xmlns.com/foaf/0.1/"),
		stat: NewNS("http://www.w3.org/ns/posix/stat#"),
	}
)

type NS string

func NewNS(base string) (ns NS) {
	return NS(base)
}

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

// frag = lambda x: x[x.find('#')==-1 and len(x) or x.find('#'):len(x)-(x[-1]=='>')]
// unfrag = lambda x: '#' in x and (x[:x.find('#')==-1 and len(x) or x.find('#')] + (x[0]=='<' and '>' or '')) or x
// cpfrag = lambda x,y: unfrag(y)[-1] == '>' and unfrag(y)[:-1]+frag(x)+'>' or unfrag(y)+frag(x)
