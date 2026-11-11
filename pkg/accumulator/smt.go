package accumulator

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrLeafIndexOutOfBounds = errors.New("leaf index exceeds Sparse Merkle Tree capacity")
	ErrInvalidDepth         = errors.New("SMT depth must be between 1 and 30")
)

// SMT is a thread-safe, fixed-depth Poseidon Sparse Merkle Tree accumulator.
// Empty subtrees are represented using precomputed ZeroHashes so O(1) root updates
// and 20-sibling witness extractions require storing only populated nodes.
type SMT struct {
	mu         sync.RWMutex
	depth      int
	zeroHashes [][]byte
	// nodes[level][index] stores the 32-byte Poseidon hash at (level, index)
	// level 0 = leaves, level depth = root (index 0).
	nodes []map[uint32][]byte
}

// NewSMT initializes a Poseidon Sparse Merkle Tree of the given depth (default 20).
func NewSMT(depth int) (*SMT, error) {
	if depth <= 0 || depth > 30 {
		return nil, ErrInvalidDepth
	}
	InitPoseidonParams()

	zeroHashes := make([][]byte, depth+1)
	zeroHashes[0] = make([]byte, 32)
	for lvl := 1; lvl <= depth; lvl++ {
		zeroHashes[lvl] = PoseidonHash2(zeroHashes[lvl-1], zeroHashes[lvl-1])
	}

	nodes := make([]map[uint32][]byte, depth+1)
	for lvl := range depth + 1 {
		nodes[lvl] = make(map[uint32][]byte)
	}

	return &SMT{
		depth:      depth,
		zeroHashes: zeroHashes,
		nodes:      nodes,
	}, nil
}

func (t *SMT) getNode(level int, idx uint32) []byte {
	if val, ok := t.nodes[level][idx]; ok {
		out := make([]byte, 32)
		copy(out, val)
		return out
	}
	out := make([]byte, 32)
	copy(out, t.zeroHashes[level])
	return out
}

func (t *SMT) setNode(level int, idx uint32, hash []byte) {
	if bytes.Equal(hash, t.zeroHashes[level]) {
		delete(t.nodes[level], idx)
		return
	}
	buf := make([]byte, 32)
	copy(buf, hash)
	t.nodes[level][idx] = buf
}

// Insert sets or updates the leaf at leafIndex and recomputes the path to the root.
func (t *SMT) Insert(leafIndex uint32, leafHash []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	maxLeaves := uint64(1) << uint(t.depth)
	if uint64(leafIndex) >= maxLeaves {
		return nil, fmt.Errorf("%w: index %d >= %d", ErrLeafIndexOutOfBounds, leafIndex, maxLeaves)
	}

	currIdx := leafIndex
	currHash := make([]byte, 32)
	if len(leafHash) > 0 {
		copy(currHash[32-len(leafHash):], leafHash)
	}
	t.setNode(0, currIdx, currHash)

	for lvl := range t.depth {
		siblingIdx := currIdx ^ 1
		siblingHash := t.getNode(lvl, siblingIdx)
		var parentHash []byte
		if currIdx&1 == 0 {
			parentHash = PoseidonHash2(currHash, siblingHash)
		} else {
			parentHash = PoseidonHash2(siblingHash, currHash)
		}
		currIdx >>= 1
		currHash = parentHash
		t.setNode(lvl+1, currIdx, currHash)
	}

	return t.getNode(t.depth, 0), nil
}

// Revoke zeros out the leaf at leafIndex and returns the updated root.
func (t *SMT) Revoke(leafIndex uint32) ([]byte, error) {
	return t.Insert(leafIndex, make([]byte, 32))
}

// GetProof extracts the depth-level sibling hashes and the 20-bit path direction bitmask
// for leafIndex. Bit i of directions is 1 if the node at level i is a right child (currIdx & 1 == 1).
func (t *SMT) GetProof(leafIndex uint32) ([][]byte, uint32, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	maxLeaves := uint64(1) << uint(t.depth)
	if uint64(leafIndex) >= maxLeaves {
		return nil, 0, fmt.Errorf("%w: index %d >= %d", ErrLeafIndexOutOfBounds, leafIndex, maxLeaves)
	}

	siblings := make([][]byte, t.depth)
	var directions uint32
	currIdx := leafIndex

	for lvl := range t.depth {
		if currIdx&1 == 1 {
			directions |= (1 << uint(lvl))
		}
		siblingIdx := currIdx ^ 1
		siblings[lvl] = t.getNode(lvl, siblingIdx)
		currIdx >>= 1
	}

	return siblings, directions, nil
}

// Root returns the current 32-byte Poseidon root of the Sparse Merkle Tree.
func (t *SMT) Root() []byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.getNode(t.depth, 0)
}

// ActiveLeafCount returns the number of non-zero leaves currently in the tree.
func (t *SMT) ActiveLeafCount() uint32 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return uint32(len(t.nodes[0]))
}

// VerifyProof verifies an SMT inclusion proof out-of-circuit.
func VerifyProof(root, leafHash []byte, siblings [][]byte, directions uint32) bool {
	curr := make([]byte, 32)
	copy(curr, leafHash)
	for lvl := range siblings {
		if (directions>>uint(lvl))&1 == 1 {
			curr = PoseidonHash2(siblings[lvl], curr)
		} else {
			curr = PoseidonHash2(curr, siblings[lvl])
		}
	}
	return bytes.Equal(curr, root)
}
