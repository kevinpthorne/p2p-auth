package circuit

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/kevinpthorne/p2p-auth/pkg/accumulator"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
)

func TestMeshAuthCircuitEndToEnd(t *testing.T) {
	kb, err := DefaultKeys()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	smt, err := accumulator.NewSMT(accumulator.DefaultSMTDepth)
	if err != nil {
		t.Fatalf("NewSMT failed: %v", err)
	}

	var secretEl fr.Element
	_, _ = secretEl.SetRandom()
	secretBytes := accumulator.FieldElementToBytes(secretEl)

	peerID := "12D3KooWTestNodePeerID1234567890"
	namespace := "p2p-anycast"
	manifestPayload := []byte(`{"service_pattern":"pbx-*","allowed_ports":[{"start":5060,"end":5061}]}`)
	claimsCommitment := accumulator.PoseidonBytes(manifestPayload)
	serial := uint64(42)
	now := time.Now().Unix()
	notBefore := now - 3600
	notAfter := now + 86400
	leafIndex := uint32(7)

	leafHash := accumulator.ComputeLeafCommitment(secretBytes, peerID, namespace, claimsCommitment, serial, notBefore, notAfter)
	epochRoot, err := smt.Insert(leafIndex, leafHash)
	if err != nil {
		t.Fatalf("SMT Insert failed: %v", err)
	}

	siblings, directions, err := smt.GetProof(leafIndex)
	if err != nil {
		t.Fatalf("SMT GetProof failed: %v", err)
	}

	cred := &authpb.VerifiableCredential{
		Id:               "urn:uuid:test-1",
		Issuer:           "did:p2p:ca-root",
		Subject:          "did:p2p:" + peerID,
		Namespace:        namespace,
		SerialNumber:     serial,
		NotBefore:        notBefore,
		NotAfter:         notAfter,
		ManifestPayload:  manifestPayload,
		ClaimsCommitment: claimsCommitment,
		CredentialSecret: secretBytes,
		EpochId:          1,
		EpochRoot:        epochRoot,
		LeafIndex:        leafIndex,
		MerkleSiblings:   siblings,
		PathDirections:   directions,
	}

	challenge := make([]byte, 32)
	_, _ = rand.Read(challenge)

	// 1. Disclosed Claims Mode (ClaimsCommitment == PoseidonBytes(manifestPayload))
	startProve := time.Now()
	vpDisclosed, err := kb.ProvePresentation(cred, peerID, challenge, now, true)
	if err != nil {
		t.Fatalf("ProvePresentation (disclosed) failed: %v", err)
	}
	proveDuration := time.Since(startProve)

	startVerify := time.Now()
	if err := VerifyPresentation(kb.VK, vpDisclosed, epochRoot); err != nil {
		t.Fatalf("VerifyPresentation (disclosed) failed: %v", err)
	}
	verifyDuration := time.Since(startVerify)
	t.Logf("Groth16 Proof size: %d bytes | Prove time: %v | Verify time: %v", len(vpDisclosed.Groth16Proof), proveDuration, verifyDuration)

	// 2. Zero-Knowledge Membership Mode (ClaimsCommitment == 0)
	vpZK, err := kb.ProvePresentation(cred, peerID, challenge, now, false)
	if err != nil {
		t.Fatalf("ProvePresentation (ZK mode) failed: %v", err)
	}
	if err := VerifyPresentation(kb.VK, vpZK, epochRoot); err != nil {
		t.Fatalf("VerifyPresentation (ZK mode) failed: %v", err)
	}

	// 3. Negative Checks: Wrong Peer ID, Wrong Namespace, Tampered Claims, Expired Timestamp, Revoked Root
	vpWrongPeer := *vpDisclosed
	vpWrongPeer.PeerId = "12D3KooWSpoofedPeerID99999"
	if err := VerifyPresentation(kb.VK, &vpWrongPeer, epochRoot); err == nil {
		t.Fatalf("Expected verification failure for spoofed Peer ID")
	}

	vpWrongNS := *vpDisclosed
	vpWrongNS.Namespace = "p2p-vpn"
	if err := VerifyPresentation(kb.VK, &vpWrongNS, epochRoot); err == nil {
		t.Fatalf("Expected verification failure for mismatched Namespace")
	}

	vpTamperedClaims := *vpDisclosed
	vpTamperedClaims.ClaimsCommitment = accumulator.PoseidonBytes([]byte("tampered-manifest"))
	if err := VerifyPresentation(kb.VK, &vpTamperedClaims, epochRoot); err == nil {
		t.Fatalf("Expected verification failure for tampered ClaimsCommitment")
	}

	// Expired timestamp check at prove time
	if _, err := kb.ProvePresentation(cred, peerID, challenge, notAfter+100, true); err == nil {
		t.Fatalf("Expected circuit constraint failure for expired timestamp")
	}

	// Revocation check: revoke leaf 7 and verify old presentation fails against new epoch root
	revokedRoot, err := smt.Revoke(leafIndex)
	if err != nil {
		t.Fatalf("SMT Revoke failed: %v", err)
	}
	if err := VerifyPresentation(kb.VK, vpDisclosed, revokedRoot); err == nil {
		t.Fatalf("Expected verification failure against post-revocation epoch root")
	}
}
