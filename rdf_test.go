package gold

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRDFBrack(t *testing.T) {
	assert.Equal(t, "<test>", brack("test"))
	assert.Equal(t, "<test", brack("<test"))
	assert.Equal(t, "test>", brack("test>"))
}

func TestRDFDebrack(t *testing.T) {
	assert.Equal(t, "a", debrack("a"))
	assert.Equal(t, "test", debrack("<test>"))
	assert.Equal(t, "<test", debrack("<test"))
	assert.Equal(t, "test>", debrack("test>"))
}

func TestDefrag(t *testing.T) {
	assert.Equal(t, "test", defrag("test"))
	assert.Equal(t, "test", defrag("test#me"))
}
