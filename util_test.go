package gold

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLinkHeaderParser(t *testing.T) {
	l := ParseLinkHeader("<http://www.w3.org/ns/ldp#Container>; rel=\"type\"")
	assert.NotEmpty(t, l.headers)
	assert.True(t, l.MatchUri("http://www.w3.org/ns/ldp#Container"))
	assert.False(t, l.MatchUri("http://www.w3.org/ns/ldp#Resource"))
	assert.Equal(t, "http://www.w3.org/ns/ldp#Container", l.MatchRel("type"))
}

func TestPreferHeaderParser(t *testing.T) {
	l := ParsePreferHeader("return=representation; omit=\"http://www.w3.org/ns/ldp#PreferMembership http://www.w3.org/ns/ldp#PreferContainment\"")
	assert.NotEmpty(t, l.headers)
	assert.Equal(t, 2, len(l.Omits()))
	for i, uri := range l.Omits() {
		if i == 0 {
			assert.Equal(t, "http://www.w3.org/ns/ldp#PreferMembership", uri)
		} else {
			assert.Equal(t, "http://www.w3.org/ns/ldp#PreferContainment", uri)
		}
	}

	l = ParsePreferHeader("return=representation; include=\"http://www.w3.org/ns/ldp#PreferMembership http://www.w3.org/ns/ldp#PreferContainment\"")
	assert.NotEmpty(t, l.headers)
	assert.Equal(t, 2, len(l.Includes()))
	for i, uri := range l.Includes() {
		if i == 0 {
			assert.Equal(t, "http://www.w3.org/ns/ldp#PreferMembership", uri)
		} else {
			assert.Equal(t, "http://www.w3.org/ns/ldp#PreferContainment", uri)
		}
	}
}
