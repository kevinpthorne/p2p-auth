package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/kevinpthorne/p2p-auth/pkg/accumulator"
)

// MeshAuthCircuit defines the BN254 Groth16 Zero-Knowledge Verifiable Presentation circuit.
// It proves that the Holder possesses a valid, non-revoked VerifiableCredential in the
// Sparse Merkle Tree with root EpochRoot, scoped to NamespaceHash and PeerIDHash,
// bound to the verifier's SessionChallenge via ChallengeTag, within its validity window,
// and optionally discloses or hides ClaimsCommitment.
type MeshAuthCircuit struct {
	// Public inputs
	EpochRoot        frontend.Variable `gnark:",public"`
	CurrentTimestamp frontend.Variable `gnark:",public"`
	PeerIDHash       frontend.Variable `gnark:",public"`
	NamespaceHash    frontend.Variable `gnark:",public"`
	ClaimsCommitment frontend.Variable `gnark:",public"` // 0 for pure ZK membership, or PoseidonBytes(manifest_payload)
	SessionChallenge frontend.Variable `gnark:",public"`
	ChallengeTag     frontend.Variable `gnark:",public"`

	// Private witness
	Secret         frontend.Variable
	PeerID         frontend.Variable
	Namespace      frontend.Variable
	NodeClaimsHash frontend.Variable
	Serial         frontend.Variable
	NotBefore      frontend.Variable
	NotAfter       frontend.Variable
	MerkleSiblings [accumulator.DefaultSMTDepth]frontend.Variable
	PathDirections [accumulator.DefaultSMTDepth]frontend.Variable
}

func sbox5Circuit(api frontend.API, x frontend.Variable) frontend.Variable {
	x2 := api.Mul(x, x)
	x4 := api.Mul(x2, x2)
	return api.Mul(x4, x)
}

func poseidonPermuteCircuit(api frontend.API, state *[accumulator.PoseidonWidth]frontend.Variable) {
	accumulator.InitPoseidonParams()
	halfF := accumulator.PoseidonFullRounds / 2

	for r := range accumulator.PoseidonTotalRounds {
		// 1. AddRoundConstants
		for i := range accumulator.PoseidonWidth {
			var rcBig big.Int
			accumulator.RoundConstants[r][i].BigInt(&rcBig)
			state[i] = api.Add(state[i], &rcBig)
		}

		// 2. SubWords (S-box x^5)
		if r < halfF || r >= halfF+accumulator.PoseidonPartialRounds {
			for i := range accumulator.PoseidonWidth {
				state[i] = sbox5Circuit(api, state[i])
			}
		} else {
			state[0] = sbox5Circuit(api, state[0])
		}

		// 3. MixLayer
		var next [accumulator.PoseidonWidth]frontend.Variable
		for i := range accumulator.PoseidonWidth {
			acc := frontend.Variable(0)
			for j := range accumulator.PoseidonWidth {
				var mdsBig big.Int
				accumulator.MDSMatrix[i][j].BigInt(&mdsBig)
				acc = api.Add(acc, api.Mul(&mdsBig, state[j]))
			}
			next[i] = acc
		}
		*state = next
	}
}

// PoseidonCircuit computes the in-circuit rate-2 BN254 Poseidon sponge hash,
// matching accumulator.PoseidonHash bit-for-bit.
func PoseidonCircuit(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	var state [accumulator.PoseidonWidth]frontend.Variable
	state[0] = len(inputs)
	state[1] = 0
	state[2] = 0

	for i := 0; i < len(inputs); i += 2 {
		state[1] = api.Add(state[1], inputs[i])
		if i+1 < len(inputs) {
			state[2] = api.Add(state[2], inputs[i+1])
		}
		poseidonPermuteCircuit(api, &state)
	}
	return state[1]
}

// Define declares the R1CS constraints for MeshAuthCircuit.
func (c *MeshAuthCircuit) Define(api frontend.API) error {
	// 1. Identity & Namespace Binding
	computedPeerHash := PoseidonCircuit(api, c.PeerID)
	api.AssertIsEqual(c.PeerIDHash, computedPeerHash)

	computedNsHash := PoseidonCircuit(api, c.Namespace)
	api.AssertIsEqual(c.NamespaceHash, computedNsHash)

	// 2. Non-Replay Session Challenge Binding: ChallengeTag == Poseidon(Secret, SessionChallenge)
	computedChallengeTag := PoseidonCircuit(api, c.Secret, c.SessionChallenge)
	api.AssertIsEqual(c.ChallengeTag, computedChallengeTag)

	// 3. Validity Window: NotBefore <= CurrentTimestamp <= NotAfter (64-bit bounded comparison)
	api.AssertIsLessOrEqual(c.NotBefore, c.CurrentTimestamp)
	api.AssertIsLessOrEqual(c.CurrentTimestamp, c.NotAfter)

	// 4. Optional Opaque Manifest Disclosure / Zero-Knowledge Selector:
	// ClaimsCommitment * (ClaimsCommitment - NodeClaimsHash) == 0
	diff := api.Sub(c.ClaimsCommitment, c.NodeClaimsHash)
	api.AssertIsEqual(api.Mul(c.ClaimsCommitment, diff), 0)

	// 5. Leaf Commitment:
	// Leaf = Poseidon(Secret, PeerID, Namespace, NodeClaimsHash, Serial, NotBefore, NotAfter)
	currHash := PoseidonCircuit(
		api,
		c.Secret,
		c.PeerID,
		c.Namespace,
		c.NodeClaimsHash,
		c.Serial,
		c.NotBefore,
		c.NotAfter,
	)

	// 6. SMT Inclusion (Depth 20)
	for lvl := range accumulator.DefaultSMTDepth {
		dir := c.PathDirections[lvl]
		api.AssertIsBoolean(dir)
		sib := c.MerkleSiblings[lvl]

		// If dir == 0: left = currHash, right = sib
		// If dir == 1: left = sib, right = currHash
		left := api.Select(dir, sib, currHash)
		right := api.Select(dir, currHash, sib)
		currHash = PoseidonCircuit(api, left, right)
	}

	api.AssertIsEqual(c.EpochRoot, currHash)
	return nil
}
