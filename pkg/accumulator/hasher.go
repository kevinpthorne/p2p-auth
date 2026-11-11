package accumulator

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	// PoseidonWidth is the sponge state width t = 3 (rate = 2, capacity = 1).
	PoseidonWidth = 3
	// PoseidonFullRounds is R_F = 8 (4 before partial rounds, 4 after).
	PoseidonFullRounds = 8
	// PoseidonPartialRounds is R_P = 56 for BN254 scalar field with alpha = 5.
	PoseidonPartialRounds = 56
	// PoseidonTotalRounds is R_F + R_P = 64.
	PoseidonTotalRounds = PoseidonFullRounds + PoseidonPartialRounds
	// DefaultSMTDepth is the fixed depth of the credential Sparse Merkle Tree (2^20 = 1,048,576 leaves).
	DefaultSMTDepth = 20
)

var (
	paramsOnce     sync.Once
	RoundConstants [PoseidonTotalRounds][PoseidonWidth]fr.Element
	MDSMatrix      [PoseidonWidth][PoseidonWidth]fr.Element
)

// InitPoseidonParams deterministically initializes the BN254 Poseidon round constants
// and MDS matrix using domain-separated SHA-256 counter mode ("p2p-auth:poseidon:bn254:v1").
func InitPoseidonParams() {
	paramsOnce.Do(func() {
		for r := range PoseidonTotalRounds {
			for j := range PoseidonWidth {
				var seed [40]byte
				copy(seed[:26], "p2p-auth:poseidon:bn254:rc")
				binary.BigEndian.PutUint32(seed[26:30], uint32(r))
				binary.BigEndian.PutUint32(seed[30:34], uint32(j))
				digest := sha256.Sum256(seed[:34])
				RoundConstants[r][j].SetBytes(digest[:])
			}
		}

		// Cauchy MDS matrix over F_r: M[i][j] = 1 / (x_i + y_j) where x_i = i + 1, y_j = PoseidonWidth + j + 1.
		for i := range PoseidonWidth {
			for j := range PoseidonWidth {
				var denom fr.Element
				denom.SetUint64(uint64(i + PoseidonWidth + j + 2))
				MDSMatrix[i][j].Inverse(&denom)
			}
		}
	})
}

func sbox5(x *fr.Element) {
	var x2, x4 fr.Element
	x2.Square(x)
	x4.Square(&x2)
	x.Mul(&x4, x)
}

// PoseidonPermute applies the 64-round BN254 Poseidon permutation in-place on a 3-element state.
func PoseidonPermute(state *[PoseidonWidth]fr.Element) {
	InitPoseidonParams()
	halfF := PoseidonFullRounds / 2

	for r := range PoseidonTotalRounds {
		// 1. AddRoundConstants
		for i := range PoseidonWidth {
			state[i].Add(&state[i], &RoundConstants[r][i])
		}

		// 2. SubWords (S-box x^5)
		if r < halfF || r >= halfF+PoseidonPartialRounds {
			for i := range PoseidonWidth {
				sbox5(&state[i])
			}
		} else {
			sbox5(&state[0])
		}

		// 3. MixLayer (multiply by MDSMatrix)
		var next [PoseidonWidth]fr.Element
		for i := range PoseidonWidth {
			for j := range PoseidonWidth {
				var prod fr.Element
				prod.Mul(&MDSMatrix[i][j], &state[j])
				next[i].Add(&next[i], &prod)
			}
		}
		*state = next
	}
}

// PoseidonHash absorbs field elements into a rate-2 Poseidon sponge (capacity element initialized to len(inputs))
// and squeezes a single BN254 scalar field element.
func PoseidonHash(inputs ...fr.Element) fr.Element {
	InitPoseidonParams()
	var state [PoseidonWidth]fr.Element
	state[0].SetUint64(uint64(len(inputs)))

	for i := 0; i < len(inputs); i += 2 {
		state[1].Add(&state[1], &inputs[i])
		if i+1 < len(inputs) {
			state[2].Add(&state[2], &inputs[i+1])
		}
		PoseidonPermute(&state)
	}
	return state[1]
}

// PoseidonHash2 hashes two 32-byte field elements (left, right) for Merkle tree nodes.
func PoseidonHash2(left, right []byte) []byte {
	var l, r fr.Element
	l.SetBytes(left)
	r.SetBytes(right)
	out := PoseidonHash(l, r)
	b := out.Bytes()
	return b[:]
}

// RawBytesToField deterministically maps arbitrary bytes into a single BN254 scalar field element
// using a chunked 31-byte sponge construction.
func RawBytesToField(data []byte) fr.Element {
	InitPoseidonParams()
	if len(data) == 0 {
		var zero fr.Element
		return zero
	}
	var chunks []fr.Element
	for i := 0; i < len(data); i += 31 {
		end := i + 31
		if end > len(data) {
			end = len(data)
		}
		var el fr.Element
		el.SetBytes(data[i:end])
		chunks = append(chunks, el)
	}
	var lenEl fr.Element
	lenEl.SetUint64(uint64(len(data)))
	chunks = append(chunks, lenEl)
	return PoseidonHash(chunks...)
}

// PoseidonBytes maps arbitrary-length bytes (manifest_payload, peer_id, namespace) into a 32-byte
// BN254 field element commitment: Poseidon(RawBytesToField(data)).
func PoseidonBytes(data []byte) []byte {
	scalar := RawBytesToField(data)
	out := PoseidonHash(scalar)
	b := out.Bytes()
	return b[:]
}

// FieldElementToBytes converts an fr.Element to a canonical 32-byte big-endian slice.
func FieldElementToBytes(el fr.Element) []byte {
	b := el.Bytes()
	return b[:]
}

// BigIntFromBytes converts canonical 32-byte big-endian field bytes into *big.Int.
func BigIntFromBytes(b []byte) *big.Int {
	var el fr.Element
	el.SetBytes(b)
	var out big.Int
	el.BigInt(&out)
	return &out
}

// ComputeChallengeTag computes Poseidon(Secret, SessionChallenge) as a 32-byte slice.
func ComputeChallengeTag(secretBytes, challengeBytes []byte) []byte {
	var sec, chal fr.Element
	sec.SetBytes(secretBytes)
	chal.SetBytes(challengeBytes)
	out := PoseidonHash(sec, chal)
	b := out.Bytes()
	return b[:]
}

// ComputeLeafCommitment computes the Verifiable Credential leaf hash:
// Leaf = Poseidon(Secret, PeerIDScalar, NamespaceScalar, NodeClaimsHash, Serial, NotBefore, NotAfter)
func ComputeLeafCommitment(secretBytes []byte, peerID string, namespace string, claimsCommitment []byte, serial uint64, notBefore, notAfter int64) []byte {
	var secret, claims fr.Element
	secret.SetBytes(secretBytes)
	claims.SetBytes(claimsCommitment)

	peerScalar := RawBytesToField([]byte(peerID))
	nsScalar := RawBytesToField([]byte(namespace))

	var serialEl, nbEl, naEl fr.Element
	serialEl.SetUint64(serial)
	nbEl.SetInt64(notBefore)
	naEl.SetInt64(notAfter)

	leaf := PoseidonHash(secret, peerScalar, nsScalar, claims, serialEl, nbEl, naEl)
	b := leaf.Bytes()
	return b[:]
}
