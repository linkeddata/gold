package gold

import (
	"log"
)

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
}
