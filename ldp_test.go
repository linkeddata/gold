package gold

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinkHeaderParser(t *testing.T) {
	l := ParseLinkHeader("")
	assert.Equal(t, "", l.MatchRel("acl"))

	l = ParseLinkHeader("<http://www.w3.org/ns/ldp#Container>; rel='type'")
	assert.NotEmpty(t, l.headers)
	assert.True(t, l.MatchURI("http://www.w3.org/ns/ldp#Container"))
	assert.False(t, l.MatchURI("http://www.w3.org/ns/ldp#Resource"))
	assert.Equal(t, "http://www.w3.org/ns/ldp#Container", l.MatchRel("type"))

	l = ParseLinkHeader("<http://www.w3.org/ns/ldp#Container>; rel=\"type\", <http://www.w3.org/ns/ldp#Resource>; rel=\"type\"")
	assert.NotEmpty(t, l.headers)
	assert.True(t, l.MatchURI("http://www.w3.org/ns/ldp#Container"))
	assert.True(t, l.MatchURI("http://www.w3.org/ns/ldp#Resource"))
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

func TestNewUUID(t *testing.T) {
	uuid := NewUUID()
	assert.Equal(t, 32, len(uuid))
}
