package circuit

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/kevinpthorne/p2p-auth/pkg/accumulator"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
)

// KeyBundle holds the compiled R1CS constraint system, Groth16 ProvingKey, and VerifyingKey.
type KeyBundle struct {
	CCS constraint.ConstraintSystem
	PK  groth16.ProvingKey
	VK  groth16.VerifyingKey
}

var (
	defaultBundleOnce sync.Once
	defaultBundle     *KeyBundle
	defaultBundleErr  error
)

// Setup compiles MeshAuthCircuit over BN254 and performs Groth16 key generation.
func Setup() (*KeyBundle, error) {
	accumulator.InitPoseidonParams()
	var circuit MeshAuthCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("compiling MeshAuthCircuit: %w", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("groth16 setup: %w", err)
	}
	return &KeyBundle{
		CCS: ccs,
		PK:  pk,
		VK:  vk,
	}, nil
}

// DefaultKeys returns a process-cached KeyBundle for fast in-process proving/verification.
func DefaultKeys() (*KeyBundle, error) {
	defaultBundleOnce.Do(func() {
		defaultBundle, defaultBundleErr = Setup()
	})
	return defaultBundle, defaultBundleErr
}

// SaveKeys writes the ProvingKey and VerifyingKey to disk.
func (kb *KeyBundle) SaveKeys(pkPath, vkPath string) error {
	if pkPath != "" {
		f, err := os.OpenFile(pkPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("creating proving key file: %w", err)
		}
		if _, err := kb.PK.WriteTo(f); err != nil {
			f.Close()
			return fmt.Errorf("writing proving key: %w", err)
		}
		f.Close()
	}
	if vkPath != "" {
		f, err := os.OpenFile(vkPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("creating verifying key file: %w", err)
		}
		if _, err := kb.VK.WriteTo(f); err != nil {
			f.Close()
			return fmt.Errorf("writing verifying key: %w", err)
		}
		f.Close()
	}
	return nil
}

// LoadKeys loads the compiled circuit alongside persisted ProvingKey and VerifyingKey files.
func LoadKeys(pkPath, vkPath string) (*KeyBundle, error) {
	accumulator.InitPoseidonParams()
	var circuit MeshAuthCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("compiling MeshAuthCircuit: %w", err)
	}

	var pk groth16.ProvingKey
	if pkPath != "" {
		f, err := os.Open(pkPath)
		if err != nil {
			return nil, fmt.Errorf("opening proving key: %w", err)
		}
		pk = groth16.NewProvingKey(ecc.BN254)
		if _, err := pk.ReadFrom(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("reading proving key: %w", err)
		}
		f.Close()
	}

	var vk groth16.VerifyingKey
	if vkPath != "" {
		f, err := os.Open(vkPath)
		if err != nil {
			return nil, fmt.Errorf("opening verifying key: %w", err)
		}
		vk = groth16.NewVerifyingKey(ecc.BN254)
		if _, err := vk.ReadFrom(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("reading verifying key: %w", err)
		}
		f.Close()
	}

	return &KeyBundle{CCS: ccs, PK: pk, VK: vk}, nil
}

// ProvePresentation generates a compressed BN254 Groth16 VerifiablePresentation from a VerifiableCredential.
// If discloseClaims is false, ClaimsCommitment in the presentation is set to 0 (pure ZK membership mode).
func (kb *KeyBundle) ProvePresentation(cred *authpb.VerifiableCredential, peerID string, sessionChallenge []byte, currentTimestamp int64, discloseClaims bool) (*authpb.VerifiablePresentation, error) {
	if len(cred.MerkleSiblings) != accumulator.DefaultSMTDepth {
		return nil, fmt.Errorf("expected %d merkle siblings, got %d", accumulator.DefaultSMTDepth, len(cred.MerkleSiblings))
	}

	peerScalar := accumulator.RawBytesToField([]byte(peerID))
	peerHash := accumulator.PoseidonHash(peerScalar)

	nsScalar := accumulator.RawBytesToField([]byte(cred.Namespace))
	nsHash := accumulator.PoseidonHash(nsScalar)

	var secretEl, nodeClaimsEl, chalEl fr.Element
	secretEl.SetBytes(cred.CredentialSecret)
	nodeClaimsEl.SetBytes(cred.ClaimsCommitment)
	chalEl.SetBytes(sessionChallenge)

	chalTagEl := accumulator.PoseidonHash(secretEl, chalEl)

	var disclosedClaimsEl fr.Element
	var disclosedClaimsBytes []byte
	if discloseClaims {
		disclosedClaimsEl = nodeClaimsEl
		disclosedClaimsBytes = make([]byte, len(cred.ClaimsCommitment))
		copy(disclosedClaimsBytes, cred.ClaimsCommitment)
	} else {
		disclosedClaimsBytes = make([]byte, 32)
	}

	var rootEl fr.Element
	rootEl.SetBytes(cred.EpochRoot)

	var peerScalarBig, peerHashBig, nsScalarBig, nsHashBig big.Int
	var secretBig, nodeClaimsBig, disclosedClaimsBig, chalBig, chalTagBig, rootBig big.Int
	peerScalar.BigInt(&peerScalarBig)
	peerHash.BigInt(&peerHashBig)
	nsScalar.BigInt(&nsScalarBig)
	nsHash.BigInt(&nsHashBig)
	secretEl.BigInt(&secretBig)
	nodeClaimsEl.BigInt(&nodeClaimsBig)
	disclosedClaimsEl.BigInt(&disclosedClaimsBig)
	chalEl.BigInt(&chalBig)
	chalTagEl.BigInt(&chalTagBig)
	rootEl.BigInt(&rootBig)

	assignment := MeshAuthCircuit{
		EpochRoot:        &rootBig,
		CurrentTimestamp: currentTimestamp,
		PeerIDHash:       &peerHashBig,
		NamespaceHash:    &nsHashBig,
		ClaimsCommitment: &disclosedClaimsBig,
		SessionChallenge: &chalBig,
		ChallengeTag:     &chalTagBig,
		Secret:           &secretBig,
		PeerID:           &peerScalarBig,
		Namespace:        &nsScalarBig,
		NodeClaimsHash:   &nodeClaimsBig,
		Serial:           cred.SerialNumber,
		NotBefore:        cred.NotBefore,
		NotAfter:         cred.NotAfter,
	}

	for lvl := range accumulator.DefaultSMTDepth {
		assignment.MerkleSiblings[lvl] = accumulator.BigIntFromBytes(cred.MerkleSiblings[lvl])
		if (cred.PathDirections>>uint(lvl))&1 == 1 {
			assignment.PathDirections[lvl] = 1
		} else {
			assignment.PathDirections[lvl] = 0
		}
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("creating circuit witness: %w", err)
	}

	proof, err := groth16.Prove(kb.CCS, kb.PK, witness)
	if err != nil {
		return nil, fmt.Errorf("generating groth16 proof: %w", err)
	}

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serializing compressed groth16 proof: %w", err)
	}

	chalTagBytes := chalTagEl.Bytes()
	return &authpb.VerifiablePresentation{
		EpochId:          cred.EpochId,
		Namespace:        cred.Namespace,
		PeerId:           peerID,
		ClaimsCommitment: disclosedClaimsBytes,
		SessionChallenge: sessionChallenge,
		ChallengeTag:     chalTagBytes[:],
		Timestamp:        currentTimestamp,
		Groth16Proof:     proofBuf.Bytes(),
	}, nil
}

// VerifyPresentation verifies a Groth16 VerifiablePresentation against the trusted EpochRoot.
func VerifyPresentation(vk groth16.VerifyingKey, vp *authpb.VerifiablePresentation, trustedEpochRoot []byte) error {
	if vp == nil {
		return fmt.Errorf("verifiable presentation is nil")
	}

	peerScalar := accumulator.RawBytesToField([]byte(vp.PeerId))
	peerHash := accumulator.PoseidonHash(peerScalar)

	nsScalar := accumulator.RawBytesToField([]byte(vp.Namespace))
	nsHash := accumulator.PoseidonHash(nsScalar)

	var rootEl, claimsEl, chalEl, chalTagEl fr.Element
	rootEl.SetBytes(trustedEpochRoot)
	claimsEl.SetBytes(vp.ClaimsCommitment)
	chalEl.SetBytes(vp.SessionChallenge)
	chalTagEl.SetBytes(vp.ChallengeTag)

	var rootBig, peerHashBig, nsHashBig, claimsBig, chalBig, chalTagBig big.Int
	rootEl.BigInt(&rootBig)
	peerHash.BigInt(&peerHashBig)
	nsHash.BigInt(&nsHashBig)
	claimsEl.BigInt(&claimsBig)
	chalEl.BigInt(&chalBig)
	chalTagEl.BigInt(&chalTagBig)

	pubAssignment := MeshAuthCircuit{
		EpochRoot:        &rootBig,
		CurrentTimestamp: vp.Timestamp,
		PeerIDHash:       &peerHashBig,
		NamespaceHash:    &nsHashBig,
		ClaimsCommitment: &claimsBig,
		SessionChallenge: &chalBig,
		ChallengeTag:     &chalTagBig,
	}

	pubWitness, err := frontend.NewWitness(&pubAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("constructing public witness: %w", err)
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(vp.Groth16Proof)); err != nil {
		return fmt.Errorf("decoding groth16 proof bytes: %w", err)
	}

	if err := groth16.Verify(proof, vk, pubWitness); err != nil {
		return fmt.Errorf("groth16 verification failed: %w", err)
	}
	return nil
}
