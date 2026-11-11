package cred

import (
	"bytes"
	"testing"
)

func TestOpaqueEnvelopeMultiAppAgnosticism(t *testing.T) {
	pub, priv, err := GenerateCAKeyPair()
	if err != nil {
		t.Fatalf("GenerateCAKeyPair failed: %v", err)
	}

	// 1. JSON/protobuf style opaque payload under custom context "p2p-anycast:ca:manifest:v1"
	anycastPayload := RenderManifestTemplate(
		[]byte(`{"serial_number":1,"subject_id":"{{SUBJECT_ID}}","libp2p_peer_id":"{{PEER_ID}}","capabilities":[{"service_pattern":"pbx-*"}]}`),
		"12D3KooWEdgeNodePeerID111",
		"edge-us-east-01",
	)
	anycastCtx := "p2p-anycast:ca:manifest:v1"

	sigAnycast, err := SignOpaquePayload(priv, anycastPayload, anycastCtx)
	if err != nil {
		t.Fatalf("SignOpaquePayload (anycast) failed: %v", err)
	}
	if !VerifyOpaquePayload(pub, anycastPayload, anycastCtx, sigAnycast) {
		t.Fatalf("VerifyOpaquePayload (anycast) failed")
	}
	// Wrong context must fail
	if VerifyOpaquePayload(pub, anycastPayload, "p2p-vpn-auth", sigAnycast) {
		t.Fatalf("expected verification failure for wrong domain_context")
	}
	// Tampered payload must fail
	if VerifyOpaquePayload(pub, append(anycastPayload, ' '), anycastCtx, sigAnycast) {
		t.Fatalf("expected verification failure for tampered payload")
	}

	// 2. Pipe-delimited routing string under custom context "p2p-vpn-auth"
	vpnPayload := RenderManifestTemplate(
		[]byte("{{PEER_ID}}|10.200.0.1/24"),
		"12D3KooWVpnNodePeerID222",
		"vpn-node-1",
	)
	if string(vpnPayload) != "12D3KooWVpnNodePeerID222|10.200.0.1/24" {
		t.Fatalf("unexpected rendered VPN template: %s", string(vpnPayload))
	}
	vpnCtx := "p2p-vpn-auth"

	sigVPN, err := SignOpaquePayload(priv, vpnPayload, vpnCtx)
	if err != nil {
		t.Fatalf("SignOpaquePayload (vpn) failed: %v", err)
	}
	if !VerifyOpaquePayload(pub, vpnPayload, vpnCtx, sigVPN) {
		t.Fatalf("VerifyOpaquePayload (vpn) failed")
	}

	// 3. ClaimsCommitment determinism and collision resistance
	commitAnycast := ComputeClaimsCommitment(anycastPayload)
	commitVPN := ComputeClaimsCommitment(vpnPayload)
	if len(commitAnycast) != 32 || len(commitVPN) != 32 {
		t.Fatalf("expected 32-byte Poseidon commitments")
	}
	if bytes.Equal(commitAnycast, commitVPN) {
		t.Fatalf("expected distinct commitments for distinct opaque payloads")
	}
}
