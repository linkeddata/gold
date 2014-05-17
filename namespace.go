/*
	Copyright (c) 2012 Kier Davis

	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
	associated documentation files (the "Software"), to deal in the Software without restriction,
	including without limitation the rights to use, copy, modify, merge, publish, distribute,
	sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all copies or substantial
	portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
	NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
	OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
	CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package gold

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

var lookupCache = make(map[string]string)

// A Namespace represents a namespace URI.
type Namespace string

// Common namespaces.
var (
	RDF     = NewNamespace("http://www.w3.org/1999/02/22-rdf-syntax-ns#")
	RDFS    = NewNamespace("http://www.w3.org/2000/01/rdf-schema#")
	OWL     = NewNamespace("http://www.w3.org/2002/07/owl#")
	CS      = NewNamespace("http://purl.org/vocab/changeset/schema#")
	BF      = NewNamespace("http://schemas.talis.com/2006/bigfoot/configuration#")
	FRM     = NewNamespace("http://schemas.talis.com/2006/frame/schema#")
	DC      = NewNamespace("http://purl.org/dc/elements/1.1/")
	DCT     = NewNamespace("http://purl.org/dc/terms/")
	DCTYPE  = NewNamespace("http://purl.org/dc/dcmitype/")
	FOAF    = NewNamespace("http://xmlns.com/foaf/0.1/")
	BIO     = NewNamespace("http://purl.org/vocab/bio/0.1/")
	GEO     = NewNamespace("http://www.w3.org/2003/01/geo/wgs84_pos#")
	REL     = NewNamespace("http://purl.org/vocab/relationship/")
	RSS     = NewNamespace("http://purl.org/rss/1.0/")
	WN      = NewNamespace("http://xmlns.com/wordnet/1.6/")
	AIR     = NewNamespace("http://www.daml.org/2001/10/html/airport-ont#")
	CONTACT = NewNamespace("http://www.w3.org/2000/10/swap/pim/contact#")
	ICAL    = NewNamespace("http://www.w3.org/2002/12/cal/ical#")
	ICALTZD = NewNamespace("http://www.w3.org/2002/12/cal/icaltzd#")
	FRBR    = NewNamespace("http://purl.org/vocab/frbr/core#")
	AD      = NewNamespace("http://schemas.talis.com/2005/address/schema#")
	LIB     = NewNamespace("http://schemas.talis.com/2005/library/schema#")
	DIR     = NewNamespace("http://schemas.talis.com/2005/dir/schema#")
	USER    = NewNamespace("http://schemas.talis.com/2005/user/schema#")
	SV      = NewNamespace("http://schemas.talis.com/2005/service/schema#")
	MO      = NewNamespace("http://purl.org/ontology/mo/")
	STATUS  = NewNamespace("http://www.w3.org/2003/06/sw-vocab-status/ns#")
	LABEL   = NewNamespace("http://purl.org/net/vocab/2004/03/label#")
	SKOS    = NewNamespace("http://www.w3.org/2004/02/skos/core#")
	BIBO    = NewNamespace("http://purl.org/ontology/bibo/")
	OV      = NewNamespace("http://open.vocab.org/terms/")
	VOID    = NewNamespace("http://rdfs.org/ns/void#")
	DBP     = NewNamespace("http://dbpedia.org/resource/")
	DBPO    = NewNamespace("http://dbpedia.org/ontology/")
	WIKI    = NewNamespace("http://en.wikipedia.org/wiki/")
	GN      = NewNamespace("http://www.geonames.org/ontology#")
	CYC     = NewNamespace("http://sw.opencyc.org/2009/04/07/concept/en/")
	S       = NewNamespace("http://schema.org/")
	GR      = NewNamespace("http://purl.org/goodrelations/v1#")
	XSD     = NewNamespace("http://www.w3.org/2001/XMLSchema#")
)

// RDF vocab elements that are used internally by the library.
var (
	A     = RDF.Get("type")
	First = RDF.Get("first")
	Rest  = RDF.Get("rest")
	Nil   = RDF.Get("nil")
)

// Function NewNamespace creates and returns a new namespace with the given base URI.
func NewNamespace(base string) (ns Namespace) {
	return Namespace(base)
}

// Function Get returns a Term representing the base URI concatenated to the given local name.
// 
// The following code:
// 
//     ns := NewNamespace("http://www.w3.org/1999/02/22-rdf-syntax-ns#")
//     term := ns.Get("type")
//     fmt.Println(term.String())
// 
// will output:
// 
//     <http://www.w3.org/1999/02/22-rdf-syntax-ns#type>
//
func (ns Namespace) Get(name string) (term Term) {
	return NewResource(string(ns) + name)
}

// Function LookupPrefix looks up the given prefix using the prefix.cc service and returns its
// namespace URI.
func LookupPrefix(prefix string) (uri string, err error) {
	uri, ok := lookupCache[prefix]
	if ok {
		return uri, nil
	}

	reqURL := fmt.Sprintf("http://prefix.cc/%s.file.txt", prefix)

	resp, err := http.Get(reqURL)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		dataBuffer := make([]byte, 1024)
		_, err := resp.Body.Read(dataBuffer)
		if err != nil {
			return "", err
		}

		data := strings.Trim(string(dataBuffer), " \r\n\x00")
		parts := strings.Split(data, "\t")

		uri = parts[1]
		lookupCache[prefix] = uri

		return uri, nil
	}

	return "", errors.New(fmt.Sprintf("HTTP request returned status %d", resp.StatusCode))
}

// Function LoadLookupCache loads the internal prefix lookup cache from the given file.
func LoadLookupCache(cacheFile string) (err error) {
	f, err := os.Open(cacheFile)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := gob.NewDecoder(f)
	err = dec.Decode(&lookupCache)
	if err != nil {
		return err
	}

	return nil
}

// Function SaveLookupCache saves the internal prefix lookup cache to the given file.
func SaveLookupCache(cacheFile string) (err error) {
	f, err := os.Create(cacheFile)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := gob.NewEncoder(f)
	err = enc.Encode(lookupCache)
	if err != nil {
		return err
	}

	return nil
}
