package gold

import (
	"strings"
)

func init() {

}

type AnyLink interface {
	MatchRel(string) string
	MatchUri(string) bool
}

type linkheader struct {
	uri string
	rel string
}

type linkheaders struct {
	headers []*linkheader
}

type preferheader struct {
	omit    []string
	include []string
}
type preferheaders struct {
	headers []*preferheader
}

func ParsePreferHeader(header string) *preferheaders {
	ret := new(preferheaders)

	for _, v := range strings.Split(header, ",") {
		item := new(preferheader)
		if strings.HasPrefix(v, "return=representation") {
			for _, s := range strings.Split(v, ";") {
				s = strings.TrimSpace(s)
				if strings.HasPrefix(s, "omit") {
					s = strings.TrimLeft(s, "omit=")
					s = strings.TrimLeft(s, "\"")
					s = strings.TrimRight(s, "\"")
					for _, u := range strings.Split(s, " ") {
						item.omit = append(item.omit, u)
					}
				}
				if strings.HasPrefix(s, "include") {
					s = strings.TrimLeft(s, "include=")
					s = strings.TrimLeft(s, "\"")
					s = strings.TrimRight(s, "\"")
					for _, u := range strings.Split(s, " ") {
						item.include = append(item.include, u)
					}
				}
			}
			ret.headers = append(ret.headers, item)
		}
	}

	return ret
}

func (p *preferheaders) Omits() []string {
	var ret []string
	for _, v := range p.headers {
		for _, u := range v.omit {
			ret = append(ret, u)
		}
	}
	return ret
}

func (p *preferheaders) Includes() []string {
	var ret []string
	for _, v := range p.headers {
		for _, u := range v.include {
			ret = append(ret, u)
		}
	}
	return ret
}

// parse Link header and optionally filter by "rel" value
func ParseLinkHeader(header string) *linkheaders {
	ret := new(linkheaders)

	for _, v := range strings.Split(header, ",") {
		item := new(linkheader)
		for _, s := range strings.Split(v, ";") {
			s = strings.TrimSpace(s)
			if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
				s = strings.TrimLeft(s, "<")
				s = strings.TrimRight(s, ">")
				item.uri = s
			} else if strings.Index(s, "rel=") >= 0 {
				s = strings.TrimLeft(s, "rel=")
				s = strings.TrimLeft(s, "\"")
				s = strings.TrimRight(s, "\"")
				item.rel = s
			}
		}
		ret.headers = append(ret.headers, item)
	}
	return ret
}

func (l *linkheaders) MatchRel(rel string) string {
	for _, v := range l.headers {
		if v.rel == rel {
			return v.uri
		}
	}
	return ""
}

func (l *linkheaders) MatchUri(uri string) bool {
	for _, v := range l.headers {
		if v.uri == uri {
			return true
		}
	}
	return false
}
