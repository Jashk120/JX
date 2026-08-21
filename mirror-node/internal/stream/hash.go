// Package stream implements mirror-side handling of consensus stream files
// (.esf / .rsf). This file mirrors consensus-node/protocol/stream/src/running_hash.rs.
package stream

import (
	"crypto/sha256"
)

// Domain is the 4-byte prefix shared by both hash kinds: ASCII "jk-k".
var Domain = [4]byte{0x6a, 0x6b, 0x2d, 0x6b}

// ChainSeed is the running hash before any item (all-zero, §5).
var ChainSeed = [32]byte{}

// ItemHash computes SHA256(DOMAIN || "item" || serializedItem).
func ItemHash(serializedItem []byte) [32]byte {
	h := sha256.New()
	h.Write(Domain[:])
	h.Write([]byte("item"))
	h.Write(serializedItem)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ChainHash folds an item hash into the running hash:
// SHA256(DOMAIN || "chain" || runningHash || itemHash).
func ChainHash(runningHash, itemHash [32]byte) [32]byte {
	h := sha256.New()
	h.Write(Domain[:])
	h.Write([]byte("chain"))
	h.Write(runningHash[:])
	h.Write(itemHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RunningHash computes the chain across a sequence of serialized items
// starting from seed.
func RunningHash(seed [32]byte, items [][]byte) [32]byte {
	cur := seed
	for _, it := range items {
		ih := ItemHash(it)
		cur = ChainHash(cur, ih)
	}
	return cur
}
