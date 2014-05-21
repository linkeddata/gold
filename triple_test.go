package gold

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestTripleEquals(t *testing.T) {
	one := NewTriple(NewResource("a"), NewResource("b"), NewResource("c"))
	assert.True(t, one.Equal(NewTriple(NewResource("a"), NewResource("b"), NewResource("c"))))
}