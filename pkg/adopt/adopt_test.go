package adopt

import (
	"testing"
	"time"

	"github.com/kevinpthorne/p2p-auth/pkg/keystore"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
)

func TestPSKAdoptionAndHardwarePoP(t *testing.T) {
	pskID, pskSecret, pskToken, err := GeneratePSKToken()
	if err != nil {
		t.Fatalf("GeneratePSKToken failed: %v", err)
	}

	parsedID, parsedSecret, err := ParsePSKToken(pskToken)
	if err != nil {
		t.Fatalf("ParsePSKToken failed: %v", err)
	}
	if parsedID != pskID || string(parsedSecret) != string(pskSecret) {
		t.Fatalf("parsed token mismatch")
	}

	nodeKey, err := keystore.GenerateEphemeralIdentity()
	if err != nil {
		t.Fatalf("GenerateEphemeralIdentity failed: %v", err)
	}

	req := &authpb.AdoptionRequest{
		Namespace:         "app-alpha",
		SubjectId:         "node-01",
		RequestedManifest: []byte(`{"peer":"{{PEER_ID}}"}`),
		DomainContext:     "p2p-anycast:ca:manifest:v1",
	}

	if err := SignAdoptionRequest(req, nodeKey, pskToken); err != nil {
		t.Fatalf("SignAdoptionRequest failed: %v", err)
	}

	if err := VerifyAdoptionRequest(req, pskSecret, time.Now()); err != nil {
		t.Fatalf("VerifyAdoptionRequest failed on valid request: %v", err)
	}

	// Tampered PSK HMAC must be rejected
	badHMACReq := *req
	badHMACReq.PskHmac = append([]byte(nil), req.PskHmac...)
	badHMACReq.PskHmac[0] ^= 0xff
	if err := VerifyAdoptionRequest(&badHMACReq, pskSecret, time.Now()); err != ErrInvalidPSKHMAC {
		t.Fatalf("expected ErrInvalidPSKHMAC, got %v", err)
	}

	// Spoofed Peer ID must be rejected
	otherKey, _ := keystore.GenerateEphemeralIdentity()
	spoofPeerReq := *req
	spoofPeerReq.PeerId = otherKey.PeerID().String()
	if err := VerifyAdoptionRequest(&spoofPeerReq, pskSecret, time.Now()); err != ErrPeerIDMismatch {
		t.Fatalf("expected ErrPeerIDMismatch, got %v", err)
	}

	// Tampered PoP signature must be rejected
	badPoPReq := *req
	badPoPReq.PopSignature = append([]byte(nil), req.PopSignature...)
	badPoPReq.PopSignature[len(badPoPReq.PopSignature)-1] ^= 0xff
	if err := VerifyAdoptionRequest(&badPoPReq, pskSecret, time.Now()); err != ErrInvalidPoPSignature {
		t.Fatalf("expected ErrInvalidPoPSignature, got %v", err)
	}

	// Expired timestamp must be rejected
	if err := VerifyAdoptionRequest(req, pskSecret, time.Now().Add(10*time.Minute)); err != ErrTimestampOutOfWindow {
		t.Fatalf("expected ErrTimestampOutOfWindow, got %v", err)
	}
}
