package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/kevinpthorne/p2p-auth/pkg/circuit"
	"github.com/kevinpthorne/p2p-auth/pkg/client"
	"github.com/kevinpthorne/p2p-auth/pkg/cred"
	"github.com/kevinpthorne/p2p-auth/pkg/server"
	"github.com/kevinpthorne/p2p-auth/pkg/swarm"
)

func adminReq(t *testing.T, method, url, token string, body any) []byte {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshaling JSON: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("creating HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("executing HTTP request %s %s: %v", method, url, err)
	}
	defer res.Body.Close()
	respBytes, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		t.Fatalf("HTTP %s %s returned %d: %s", method, url, res.StatusCode, string(respBytes))
	}
	return respBytes
}

func TestE2ESwarmVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	adminToken := "e2e-test-admin-token"

	kb, err := circuit.DefaultKeys()
	if err != nil {
		t.Fatalf("DefaultKeys failed: %v", err)
	}

	// 1. Start Central Auth Server
	authSrv, err := server.NewAuthServer(ctx, server.Config{
		StorePath:     filepath.Join(tmpDir, "auth.db"),
		P2PListenAddr: "/ip4/127.0.0.1/tcp/0",
		HTTPAddr:      "127.0.0.1:0",
		AdminToken:    adminToken,
		EpochDuration: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewAuthServer failed: %v", err)
	}
	defer authSrv.Close()

	baseURL := "http://" + authSrv.HTTPAddr()

	// 2. Create AUTO PSK for "app-alpha" and QUEUE PSK for "app-beta" via Admin API
	var autoPSKResp struct {
		PSKID string `json:"psk_id"`
		Token string `json:"token"`
	}
	rawAuto := adminReq(t, http.MethodPost, baseURL+"/api/admin/psks", adminToken, map[string]any{
		"namespace":         "app-alpha",
		"mode":              "AUTO",
		"domain_context":    "p2p-anycast:ca:manifest:v1",
		"manifest_template": `{"peer":"{{PEER_ID}}","cap":"edge"}`,
		"max_uses":          5,
		"ttl_hours":         24,
	})
	if err := json.Unmarshal(rawAuto, &autoPSKResp); err != nil || autoPSKResp.Token == "" {
		t.Fatalf("failed to create AUTO PSK: %v (%s)", err, string(rawAuto))
	}

	var queuePSKResp struct {
		PSKID string `json:"psk_id"`
		Token string `json:"token"`
	}
	rawQueue := adminReq(t, http.MethodPost, baseURL+"/api/admin/psks", adminToken, map[string]any{
		"namespace":      "app-beta",
		"mode":           "QUEUE",
		"domain_context": "p2p-vpn-auth",
		"max_uses":       5,
		"ttl_hours":      24,
	})
	if err := json.Unmarshal(rawQueue, &queuePSKResp); err != nil || queuePSKResp.Token == "" {
		t.Fatalf("failed to create QUEUE PSK: %v (%s)", err, string(rawQueue))
	}

	// 3. Start 2 Decentralized Swarm Verifier nodes connected to Auth Server
	verifier1, err := swarm.NewVerifierNode(ctx, swarm.Config{
		ListenAddr:     "/ip4/127.0.0.1/tcp/0",
		BootstrapAddrs: []string{authSrv.Multiaddr()},
		TrustedCAPub:   authSrv.CAPublicKey(),
		VerifyingKey:   kb.VK,
	})
	if err != nil {
		t.Fatalf("NewVerifierNode 1 failed: %v", err)
	}
	defer verifier1.Close()

	verifier2, err := swarm.NewVerifierNode(ctx, swarm.Config{
		ListenAddr:     "/ip4/127.0.0.1/tcp/0",
		BootstrapAddrs: []string{authSrv.Multiaddr(), verifier1.Multiaddr()},
		TrustedCAPub:   authSrv.CAPublicKey(),
		VerifyingKey:   kb.VK,
	})
	if err != nil {
		t.Fatalf("NewVerifierNode 2 failed: %v", err)
	}
	defer verifier2.Close()

	// 4. Boot unprovisioned Node A with only AUTO PSK -> single-pass zero-touch adoption
	startAdoptA := time.Now()
	nodeADir := filepath.Join(tmpDir, "node-a")
	nodeA, err := client.NewClient(client.Config{
		Namespace:           "app-alpha",
		SubjectID:           "edge-alpha-01",
		StateDir:            nodeADir,
		AuthServerMultiaddr: authSrv.Multiaddr(),
		VerifierMultiaddr:   verifier1.Multiaddr(),
		AdoptionPSK:         autoPSKResp.Token,
		KeyBundle:           kb,
	})
	if err != nil {
		t.Fatalf("NewClient Node A failed: %v", err)
	}
	defer nodeA.Close()

	vcA, err := nodeA.EnsureEnrolled(ctx)
	if err != nil {
		t.Fatalf("Node A EnsureEnrolled (AUTO PSK) failed: %v", err)
	}
	t.Logf("Node A auto-adopted in %v: PeerID=%s Serial=%d Epoch=%d", time.Since(startAdoptA), nodeA.PeerID(), vcA.SerialNumber, vcA.EpochId)

	expectedManifestA := fmt.Sprintf(`{"peer":"%s","cap":"edge"}`, nodeA.PeerID().String())
	if string(vcA.ManifestPayload) != expectedManifestA {
		t.Fatalf("Node A manifest mismatch: got %s, want %s", string(vcA.ManifestPayload), expectedManifestA)
	}
	if !cred.VerifyOpaquePayload(authSrv.CAPublicKey(), vcA.ManifestPayload, "p2p-anycast:ca:manifest:v1", vcA.ManifestCaSignature) {
		t.Fatalf("Node A ML-DSA-87 manifest signature verification failed")
	}

	// 5. Boot unprovisioned Node B with QUEUE PSK -> waits in pending queue until Admin approves
	nodeBDir := filepath.Join(tmpDir, "node-b")
	nodeB, err := client.NewClient(client.Config{
		Namespace:           "app-beta",
		SubjectID:           "vpn-beta-01",
		StateDir:            nodeBDir,
		AuthServerMultiaddr: authSrv.Multiaddr(),
		VerifierMultiaddr:   verifier2.Multiaddr(),
		AdoptionPSK:         queuePSKResp.Token,
		KeyBundle:           kb,
	})
	if err != nil {
		t.Fatalf("NewClient Node B failed: %v", err)
	}
	defer nodeB.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := nodeB.EnsureEnrolled(ctx)
		errCh <- err
	}()

	// Wait until Node B appears in GET /api/admin/adopt/pending
	var pendingFound bool
	for range 40 {
		rawPending := adminReq(t, http.MethodGet, baseURL+"/api/admin/adopt/pending", adminToken, nil)
		var list []map[string]any
		_ = json.Unmarshal(rawPending, &list)
		for _, item := range list {
			if item["peer_id"] == nodeB.PeerID().String() {
				pendingFound = true
				break
			}
		}
		if pendingFound {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !pendingFound {
		t.Fatalf("Node B did not appear in /api/admin/adopt/pending")
	}

	// Approve Node B via POST /api/admin/adopt/approve with pipe-delimited template
	adminReq(t, http.MethodPost, baseURL+"/api/admin/adopt/approve", adminToken, map[string]any{
		"peer_id":          nodeB.PeerID().String(),
		"namespace":        "app-beta",
		"domain_context":   "p2p-vpn-auth",
		"manifest_payload": "{{PEER_ID}}|10.200.0.2/24",
	})

	if err := <-errCh; err != nil {
		t.Fatalf("Node B queue adoption failed: %v", err)
	}
	vcB := nodeB.Credential()
	expectedManifestB := fmt.Sprintf("%s|10.200.0.2/24", nodeB.PeerID().String())
	if string(vcB.ManifestPayload) != expectedManifestB {
		t.Fatalf("Node B manifest mismatch: got %s, want %s", string(vcB.ManifestPayload), expectedManifestB)
	}

	// 6. Sync Verifier nodes with latest epoch and update Node A's SMT witness to the latest epoch
	_ = verifier1.ConnectAndSync(ctx, authSrv.Multiaddr())
	_ = verifier2.ConnectAndSync(ctx, authSrv.Multiaddr())

	latestEpoch := verifier1.LatestEpoch()
	if latestEpoch == nil || latestEpoch.EpochId < vcB.EpochId {
		t.Fatalf("Verifier 1 failed to sync latest epoch")
	}

	// Refresh Node A's witness for current epoch
	sibA, dirA, err := authSrv.GetUpdatedWitness(vcA.SerialNumber)
	if err != nil {
		t.Fatalf("GetUpdatedWitness failed: %v", err)
	}
	vcA.EpochId = latestEpoch.EpochId
	vcA.EpochRoot = latestEpoch.MerkleRoot
	vcA.MerkleSiblings = sibA
	vcA.PathDirections = dirA

	// 7. Node A generates Groth16 VerifiablePresentation and verifies via Swarm Verifier 1
	challenge := make([]byte, 32)
	_, _ = rand.Read(challenge)

	vpA, err := nodeA.GenerateHandshakeProof(ctx, challenge, true)
	if err != nil {
		t.Fatalf("Node A GenerateHandshakeProof failed: %v", err)
	}

	startVerify := time.Now()
	receipt, err := nodeA.RequestSwarmTicket(ctx, vpA)
	if err != nil {
		t.Fatalf("RequestSwarmTicket failed: %v", err)
	}
	t.Logf("Swarm Verifier 1 verified Groth16 presentation and minted AuthReceipt in %v", time.Since(startVerify))

	if receipt.PeerId != nodeA.PeerID().String() || receipt.Namespace != "app-alpha" {
		t.Fatalf("unexpected AuthReceipt fields: %+v", receipt)
	}

	// Also verify locally using VerifyPeerProof
	ok, err := nodeB.VerifyPeerProof(ctx, vpA, nodeA.PeerID(), vcA.ManifestPayload, latestEpoch.MerkleRoot)
	if err != nil || !ok {
		t.Fatalf("local VerifyPeerProof failed: %v", err)
	}

	// 8. Admin revokes Node A via POST /api/admin/revoke -> emits updated epoch -> old credential fails immediately
	adminReq(t, http.MethodPost, baseURL+"/api/admin/revoke", adminToken, map[string]any{
		"serial": vcA.SerialNumber,
	})
	_ = verifier1.ConnectAndSync(ctx, authSrv.Multiaddr())

	if _, err := nodeA.RequestSwarmTicket(ctx, vpA); err == nil {
		t.Fatalf("expected swarm verification to reject revoked Node A credential")
	}
}
