package accumulator

import (
	"bytes"
	"testing"
)

func TestSMTPoseidonInsertGetProofAndRevoke(t *testing.T) {
	smt, err := NewSMT(DefaultSMTDepth)
	if err != nil {
		t.Fatalf("NewSMT failed: %v", err)
	}

	emptyRoot := smt.Root()
	if len(emptyRoot) != 32 {
		t.Fatalf("expected 32-byte root, got %d", len(emptyRoot))
	}

	leafA := PoseidonBytes([]byte("node-a-credential"))
	leafB := PoseidonBytes([]byte("node-b-credential"))

	root1, err := smt.Insert(0, leafA)
	if err != nil {
		t.Fatalf("Insert 0 failed: %v", err)
	}
	if bytes.Equal(root1, emptyRoot) {
		t.Fatalf("expected root to change after inserting leaf 0")
	}

	root2, err := smt.Insert(42, leafB)
	if err != nil {
		t.Fatalf("Insert 42 failed: %v", err)
	}

	siblings0, dir0, err := smt.GetProof(0)
	if err != nil {
		t.Fatalf("GetProof(0) failed: %v", err)
	}
	if !VerifyProof(root2, leafA, siblings0, dir0) {
		t.Fatalf("VerifyProof failed for leaf 0")
	}

	siblings42, dir42, err := smt.GetProof(42)
	if err != nil {
		t.Fatalf("GetProof(42) failed: %v", err)
	}
	if !VerifyProof(root2, leafB, siblings42, dir42) {
		t.Fatalf("VerifyProof failed for leaf 42")
	}

	// Revoke leaf 0; root must change and leaf 0's old proof must fail
	rootAfterRevoke, err := smt.Revoke(0)
	if err != nil {
		t.Fatalf("Revoke(0) failed: %v", err)
	}
	if VerifyProof(rootAfterRevoke, leafA, siblings0, dir0) {
		t.Fatalf("expected revoked leaf 0 proof to fail against updated root")
	}

	// Leaf 42 remains valid with updated proof
	siblings42New, dir42New, err := smt.GetProof(42)
	if err != nil {
		t.Fatalf("GetProof(42) after revoke failed: %v", err)
	}
	if !VerifyProof(rootAfterRevoke, leafB, siblings42New, dir42New) {
		t.Fatalf("expected leaf 42 to remain valid after leaf 0 revocation")
	}
}
