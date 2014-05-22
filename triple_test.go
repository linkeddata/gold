package gold

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTripleEquals(t *testing.T) {
	one := NewTriple(NewResource("a"), NewResource("b"), NewResource("c"))
	assert.True(t, one.Equal(NewTriple(NewResource("a"), NewResource("b"), NewResource("c"))))
}
