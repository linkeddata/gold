package gold

import (
	"sync"
)

var (
	locksL = new(sync.Mutex)
	locks  = map[string]*sync.Mutex{}
)

func lock(key string) func() {
	mu, ex := locks[key]
	if !ex { // TTAS
		locksL.Lock()
		mu, ex = locks[key]
		if !ex {
			locks[key] = new(sync.Mutex)
		}
		locksL.Unlock()
		mu = locks[key]
	}
	mu.Lock()
	return func() {
		mu.Unlock()
	}
}
