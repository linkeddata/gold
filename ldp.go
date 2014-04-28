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

func init() {

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

				if strings.HasPrefix(s, "\"") {
					s = strings.TrimLeft(s, "\"")
				}
				if strings.HasSuffix(s, "\"") {
					s = strings.TrimRight(s, "\"")
				}
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

func newUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return hex.EncodeToString(uuid), nil
}

func NewETag(path string) (string, error) {
	var (
		hash []byte
		md5s []string
		err  error
	)
	stat, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	switch {
	case stat.IsDir():
		if files, err := ioutil.ReadDir(path); err == nil {
			if !strings.HasSuffix(path, "/") {
				path = path + "/"
			}
			if len(files) == 0 {
				md5s = append(md5s, path+stat.ModTime().String())
			}
			for _, file := range files {
				h, err := NewETag(path + file.Name())
				if err != nil {
					return "", err
				}
				md5s = append(md5s, h)
			}
		}
		h := md5.New()
		io.Copy(h, bytes.NewBufferString(fmt.Sprintf("%s", md5s)))
		hash = h.Sum([]byte(""))
	default:
		f, err := os.Open(path)
		defer f.Close()
		if err != nil {
			return "", err
		}
		h := md5.New()
		io.Copy(h, f)
		hash = h.Sum([]byte(""))
	}

	return hex.EncodeToString(hash), err
}
