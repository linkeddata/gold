package gold

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
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

func TestNewUUID(t *testing.T) {
	uuid, err := newUUID()
	assert.Nil(t, err)
	assert.Equal(t, 32, len(uuid))
}

func TestETagMD5(t *testing.T) {
	fhash := "c260f684d3e6e9800d754ba966003306"
	dir := "/tmp/dirmd5"
	path := "/tmp/dirmd5/testmd5"

	err := os.MkdirAll(dir, 0755)
	assert.Nil(t, err)
	h, err := NewETag(dir)
	assert.Nil(t, err)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0666)
	assert.Nil(t, err)
	_, err = io.Copy(f, bytes.NewBufferString("test string to be hashed later"))
	f.Close()
	assert.Nil(t, err)

	h, err = NewETag(path + "123")
	assert.NotNil(t, err)
	assert.Empty(t, h)

	h, err = NewETag(path)
	assert.Nil(t, err)
	assert.Equal(t, fhash, h)

	f, err = os.OpenFile(path, os.O_RDWR, 0666)
	assert.Nil(t, err)
	_, err = io.Copy(f, bytes.NewBufferString("testing modified string"))
	f.Close()
	assert.Nil(t, err)
	h, err = NewETag(path)
	assert.NotEqual(t, fhash, h)

	err = os.RemoveAll(dir)
	assert.Nil(t, err)
}

func BenchmarkNewUUID(b *testing.B) {
	e := 0
	for i := 0; i < b.N; i++ {
		if _, err := newUUID(); err != nil {
			e += 1
		}
	}
	if e > 0 {
		b.Log(fmt.Sprintf("%d/%d failed", e, b.N))
		b.Fail()
	}
}
