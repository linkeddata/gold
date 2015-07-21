package gold

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

type linkheader struct {
	uri string
	rel string
}

// Linkheaders holds the list of Link headers
type Linkheaders struct {
	headers []*linkheader
}

type preferheader struct {
	omit    []string
	include []string
}

// Preferheaders holds the list of Prefer headers
type Preferheaders struct {
	headers []*preferheader
}

// ParsePreferHeader parses the LDP specific Prefer header
func ParsePreferHeader(header string) *Preferheaders {
	ret := new(Preferheaders)

	for _, v := range strings.Split(header, ",") {
		item := new(preferheader)
		v = strings.TrimSpace(v)
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

// Omits returns the types of resources to omit when listing an LDPC
func (p *Preferheaders) Omits() []string {
	var ret []string
	for _, v := range p.headers {
		for _, u := range v.omit {
			ret = append(ret, u)
		}
	}
	return ret
}

// Includes returns the types of resources to include when listing an LDPC
func (p *Preferheaders) Includes() []string {
	var ret []string
	for _, v := range p.headers {
		for _, u := range v.include {
			ret = append(ret, u)
		}
	}
	return ret
}

// ParseLinkHeader is a generic Link header parser
func ParseLinkHeader(header string) *Linkheaders {
	ret := new(Linkheaders)

	for _, v := range strings.Split(header, ", ") {
		item := new(linkheader)
		for _, s := range strings.Split(v, ";") {
			s = strings.TrimSpace(s)
			if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
				s = strings.TrimLeft(s, "<")
				s = strings.TrimRight(s, ">")
				item.uri = s
			} else if strings.Index(s, "rel=") >= 0 {
				s = strings.TrimLeft(s, "rel=")

				if strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") {
					s = s[1:]
				}
				if strings.HasSuffix(s, "\"") || strings.HasSuffix(s, "'") {
					s = s[:len(s)-1]
				}
				item.rel = s
			}
		}
		ret.headers = append(ret.headers, item)
	}
	return ret
}

// MatchRel attempts to match a Link header based on the rel value
func (l *Linkheaders) MatchRel(rel string) string {
	for _, v := range l.headers {
		if v.rel == rel {
			return v.uri
		}
	}
	return ""
}

// MatchURI attempts to match a Link header based on the href value
func (l *Linkheaders) MatchURI(uri string) bool {
	for _, v := range l.headers {
		if v.uri == uri {
			return true
		}
	}
	return false
}

// NewUUID generates a new UUID string
func NewUUID() string {
	uuid := make([]byte, 16)
	io.ReadFull(rand.Reader, uuid)
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return hex.EncodeToString(uuid)
}

// NewETag generates ETag
func NewETag(path string) (string, error) {
	var (
		hash []byte
		md5s string
		err  error
	)
	stat, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if stat.IsDir() {
		if files, err := ioutil.ReadDir(path); err == nil {
			if len(files) == 0 {
				md5s += stat.ModTime().String()
			}
			for _, file := range files {
				md5s += file.ModTime().String() + fmt.Sprintf("%d", file.Size())
			}
		}
	} else {
		md5s += stat.ModTime().String() + fmt.Sprintf("%d", stat.Size())
	}
	h := md5.New()
	io.Copy(h, bytes.NewBufferString(md5s))
	hash = h.Sum([]byte(""))

	return hex.EncodeToString(hash), err
}
