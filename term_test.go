package gold

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestLiteralEqual(t *testing.T) {
	var t1 Literal
	t1.Value = "test1"
	t1.Language = "en"

	assert.True(t, t1.Equal(NewLiteralWithLanguage("test1", "en")))
	assert.False(t, t1.Equal(NewLiteralWithLanguage("test2", "en")))

	assert.True(t, t1.Equal(NewLiteralWithLanguage("test1", "en")))
	assert.False(t, t1.Equal(NewLiteralWithLanguage("test1", "fr")))

	t1.Language = ""
	t1.Datatype = NewResource("http://www.w3.org/2001/XMLSchema#string")
	assert.False(t, t1.Equal(NewLiteral("test1")))
	assert.True(t, t1.Equal(NewLiteralWithDatatype("test1", NewResource("http://www.w3.org/2001/XMLSchema#string"))))
	assert.False(t, t1.Equal(NewLiteralWithDatatype("test1", NewResource("http://www.w3.org/2001/XMLSchema#int"))))
}

func TestNewLiteralWithLanguage(t *testing.T) {
	s := NewLiteralWithLanguage("test", "en")
	assert.Equal(t, "\"test\"@en", s.String())
}

func TestNewLiteralWithDatatype(t *testing.T) {
	s := NewLiteralWithDatatype("test", NewResource("http://www.w3.org/2001/XMLSchema#string"))
	assert.Equal(t, "\"test\"^^<http://www.w3.org/2001/XMLSchema#string>", s.String())
}

func TestNewLiteralWithLanguageAndDatatype(t *testing.T) {
	s := NewLiteralWithLanguageAndDatatype("test", "en", NewResource("http://www.w3.org/2001/XMLSchema#string"))
	assert.Equal(t, "\"test\"@en", s.String())

	s = NewLiteralWithLanguageAndDatatype("test", "", NewResource("http://www.w3.org/2001/XMLSchema#string"))
	assert.Equal(t, "\"test\"^^<http://www.w3.org/2001/XMLSchema#string>", s.String())
}

func TestNewBlankNode(t *testing.T) {
	id := NewBlankNode("n1")
	assert.Equal(t, "_:n1", id.String())
}

func TestNewAnonNode(t *testing.T) {
	id := NewAnonNode()
	assert.True(t, strings.Contains(id.String(), "_:anon"))
}

func TestBNodeEqual(t *testing.T) {
	var id1 BlankNode
	id1.ID = "n1"
	id2 := NewBlankNode("n1")
	assert.True(t, id1.Equal(id2))
	id3 := NewBlankNode("n2")
	assert.False(t, id1.Equal(id3))
}
