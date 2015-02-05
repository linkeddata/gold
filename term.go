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
	"fmt"
	"math/rand"
	"strings"
)

// A Term is the value of a subject, predicate or object i.e. a IRI reference, blank node or
// literal.
type Term interface {
	// Method String should return the NTriples representation of this term.
	String() string

	// Method Equal should return whether this term is equal to another.
	Equal(Term) bool
}

// Resource is an URI / IRI reference.
type Resource struct {
	URI string
}

// NewResource returns a new resource object.
func NewResource(uri string) (term Term) {
	return Term(&Resource{URI: uri})
}

// String returns the NTriples representation of this resource.
func (term Resource) String() (str string) {
	return fmt.Sprintf("<%s>", term.URI)
}

// Equal returns whether this resource is equal to another.
func (term Resource) Equal(other Term) bool {
	if spec, ok := other.(*Resource); ok {
		return term.URI == spec.URI
	}

	return false
}

// Literal is a textual value, with an associated language or datatype.
type Literal struct {
	Value    string
	Language string
	Datatype Term
}

// NewLiteral returns a new literal with the given value.
func NewLiteral(value string) (term Term) {
	return Term(&Literal{Value: value})
}

// NewLiteralWithLanguage returns a new literal with the given value and language.
func NewLiteralWithLanguage(value string, language string) (term Term) {
	return Term(&Literal{Value: value, Language: language})
}

// NewLiteralWithDatatype returns a new literal with the given value and datatype.
func NewLiteralWithDatatype(value string, datatype Term) (term Term) {
	return Term(&Literal{Value: value, Datatype: datatype})
}

// NewLiteralWithLanguageAndDatatype returns a new literal with the given value, language
// and datatype. Technically a literal cannot have both a language and a datatype, but this function
// is provided to allow creation of literal in a context where this check has already been made,
// such as in a parser.
func NewLiteralWithLanguageAndDatatype(value string, language string, datatype Term) (term Term) {
	return Term(&Literal{Value: value, Language: language, Datatype: datatype})
}

// String returns the NTriples representation of this literal.
func (term Literal) String() (str string) {
	str = term.Value
	str = strings.Replace(str, "\\", "\\\\", -1)
	str = strings.Replace(str, "\"", "\\\"", -1)
	str = strings.Replace(str, "\n", "\\n", -1)
	str = strings.Replace(str, "\r", "\\r", -1)
	str = strings.Replace(str, "\t", "\\t", -1)

	str = fmt.Sprintf("\"%s\"", str)

	if term.Language != "" {
		str += "@" + term.Language
	} else if term.Datatype != nil {
		str += "^^" + term.Datatype.String()
	}

	return str
}

// Equal returns whether this literal is equivalent to another.
func (term Literal) Equal(other Term) bool {
	spec, ok := other.(*Literal)
	if !ok {
		return false
	}

	if term.Value != spec.Value {
		return false
	}

	if term.Language != spec.Language {
		return false
	}

	if (term.Datatype == nil && spec.Datatype != nil) || (term.Datatype != nil && spec.Datatype == nil) {
		return false
	}

	if term.Datatype != nil && spec.Datatype != nil && !term.Datatype.Equal(spec.Datatype) {
		return false
	}

	return true
}

// BlankNode is an RDF blank node i.e. an unqualified URI/IRI.
type BlankNode struct {
	ID string
}

// NewBlankNode returns a new blank node with the given ID.
func NewBlankNode(id string) (term Term) {
	return Term(&BlankNode{ID: id})
}

// NewAnonNode returns a new blank node with a pseudo-randomly generated ID.
func NewAnonNode() (term Term) {
	return Term(&BlankNode{ID: fmt.Sprintf("anon%016x", rand.Int63())})
}

// String returns the NTriples representation of the blank node.
func (term BlankNode) String() (str string) {
	return "_:" + term.ID
}

// Equal returns whether this blank node is equivalent to another.
func (term BlankNode) Equal(other Term) bool {
	if spec, ok := other.(*BlankNode); ok {
		return term.ID == spec.ID
	}

	return false
}
