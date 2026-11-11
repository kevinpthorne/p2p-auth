# `p2p-auth` — Application-Agnostic Libp2p ZK-VC & PSK Adoption Appliance

`p2p-auth` is a standalone, application-agnostic authentication, first-boot PSK adoption, and Zero-Knowledge Verifiable Credential (ZK-VC) appliance for decentralized `libp2p` overlays (such as `p2p-anycast` and `p2p-vpn`).

## Architecture Overview

1. **Issuer (`p2p-auth-server`) & First-Boot PSK Adoption (`/p2p-auth/adopt/1.0.0`)**:
   - First-boot nodes initialize their persistent hardware identity (`TPM 2.0` $\to$ `Apple Secure Enclave` $\to$ `Filesystem` ECDSA P-256) and authenticate using a Pre-Shared Key (`p2p_psk_<id>_<secret_hex>`) plus a hardware Proof-of-Possession (`pop_signature`).
   - Application manifests (`manifest_payload`) are treated as **opaque bytes** scoped to a `namespace` and signed with FIPS 204 **ML-DSA-87** under any caller-specified `domain_context` (supporting `{{PEER_ID}}` and `{{SUBJECT_ID}}` template interpolation).
   - Supports **AUTO** mode (single-pass zero-touch adoption) and **QUEUE** mode (operator approval over the open adoption stream via the embedded Web Admin UI or CLI).
2. **Sparse Merkle Tree (SMT) Accumulator & Groth16 ZK-VP (`pkg/accumulator`, `pkg/circuit`)**:
   - Credentials are committed into a depth-20 BN254 Poseidon Sparse Merkle Tree ($2^{20} = 1,048,576$ leaves).
   - Nodes generate compressed BN254 Groth16 **Verifiable Presentations (`VerifiablePresentation`)** proving non-revoked membership in `namespace`, validity window compliance, non-replay `ChallengeTag` binding, and either zero-knowledge hiding (`ClaimsCommitment = 0`) or explicit disclosure (`ClaimsCommitment = PoseidonBytes(manifest_payload)`).
3. **Decentralized Verification Swarm (`p2p-auth-verifier`)**:
   - Subscribes to CA-signed `EpochBroadcast` roots over GossipSub (`/p2p-auth/epoch/1.0.0`).
   - Verifies Groth16 presentations over `/p2p-auth/verify/1.0.0` in `< 1 ms` and issues signed `AuthReceipt` tickets broadcast on `/p2p-auth/receipts/1.0.0`.
4. **Embedded Web Admin UI (`gui/`)**:
   - Built-in dark-mode SPA served by `p2p-auth-server` with real-time Server-Sent Events (SSE) audit streaming (`/api/admin/events`), PSK provisioning, pending adoption approval/rejection, manual credential minting, and one-click $O(1)$ node revocation.

## Building & Testing

```bash
# Build all binaries (bin/p2p-auth-server, bin/p2p-auth-verifier, bin/p2p-auth-client)
make build

# Run full test suite with race detector
make test
```

## Client SDK Guide

The `pkg/client` package provides a high-level, application-agnostic SDK for libp2p nodes to perform zero-touch hardware onboarding, ZK Verifiable Credential issuance, presentation proving, and local or swarm-delegated verification.

```go
import (
    "github.com/kevinpthorne/p2p-auth/pkg/client"
    "github.com/kevinpthorne/p2p-auth/pkg/keystore"
)
```

### 1. Initialize Client & Hardware Keystore

On first boot, the SDK loads or initializes a persistent hardware-anchored identity key following a strict waterfall:
$$\text{TPM 2.0} \longrightarrow \text{Apple Secure Enclave} \longrightarrow \text{Filesystem (ECDSA P-256)}$$

```go
cl, err := client.NewClient(client.Config{
    Namespace:           "p2p-anycast", // Application domain scope
    SubjectID:           "edge-us-east-01",
    StateDir:            "/var/lib/my-app/auth",
    AuthServerMultiaddr: "/ip4/198.51.100.1/tcp/4005/p2p/QmServer...",
    VerifierMultiaddr:   "/ip4/198.51.100.2/tcp/4006/p2p/QmVerifier...", // Optional swarm verifier
    AdoptionPSK:         os.Getenv("P2P_AUTH_ADOPTION_PSK"),            // e.g. p2p_psk_4ff3f270_...
    IdentityOpts: keystore.Options{
        KeyFilePath: "/var/lib/my-app/auth/identity.key",
        AllowCreate: true, // Auto-generates ECDSA P-256 if hardware coprocessor unavailable
    },
})
if err != nil {
    log.Fatalf("failed to initialize p2p-auth client: %v", err)
}
defer cl.Close()

fmt.Printf("Node Peer ID: %s (Tier: %s)\n", cl.PeerID(), cl.IdentityKey().Tier())
```

---

### 2. Zero-Touch Onboarding (`EnsureEnrolled`)

Call `EnsureEnrolled` during application bootstrap. It checks for a cached credential on disk (`credential.zkp`). If missing, it connects to the Central Auth Server over `/p2p-auth/adopt/1.0.0`, presents the hardware Proof-of-Possession signature and PSK HMAC, and receives the signed manifest and ZKP credential in a single pass:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

vc, err := cl.EnsureEnrolled(ctx)
if err != nil {
    log.Fatalf("onboarding failed: %v", err)
}

fmt.Printf("Enrolled: Serial=#%d Epoch=%d SMT Leaf=%d\n",
    vc.SerialNumber, vc.EpochId, vc.LeafIndex)

// Access application-specific opaque payload and CA signature:
manifestBytes := vc.ManifestPayload
manifestSig   := vc.ManifestCaSignature
```

- In **AUTO** mode, `EnsureEnrolled` returns immediately in one round-trip.
- In **QUEUE** mode, it holds open the `/p2p-auth/adopt/1.0.0` stream until an administrator clicks **Approve** in the Web Admin UI or runs `p2p-auth-server adopt approve`.
- Upon approval, the credential is automatically written to `StateDir/credential.zkp` (`0600`), so subsequent boots bypass network adoption entirely.

---

### 3. Generating Handshake Presentations (Prover / Holder)

During a peer-to-peer connection handshake, the listening peer provides an ephemeral 32-byte challenge nonce. The connecting node generates a 164-byte Groth16 Verifiable Presentation in under 50 ms:

```go
// 32-byte random challenge nonce from peer
challenge := make([]byte, 32)
rand.Read(challenge)

// discloseClaims = true: binds the presentation to PoseidonBytes(manifest_payload)
// discloseClaims = false: pure zero-knowledge mode (hides manifest hash completely)
vp, err := cl.GenerateHandshakeProof(ctx, challenge, true)
if err != nil {
    log.Fatalf("failed to generate Groth16 presentation: %v", err)
}

// Send vp (serialized protobuf) over your libp2p handshake stream
```

---

### 4. Verifying Peer Presentations (Verifier)

The receiving peer can verify the presentation using either **Autonomous / Local Mode** or **Delegated Swarm Mode**:

#### Mode A: Autonomous / Local Verification (Zero Network Latency)
Verify the 164-byte Groth16 proof locally in `< 1 ms` using the cached `EpochRoot` synchronized from the verification swarm:

```go
trustedEpochRoot := cachedEpoch.MerkleRoot
expectedManifest := []byte(`{"peer":"12D3KooW..."}`) // Optional: nil to skip manifest match

valid, err := cl.VerifyPeerProof(ctx, vp, remotePeerID, expectedManifest, trustedEpochRoot)
if err != nil || !valid {
    log.Printf("handshake rejected: %v", err)
    stream.Reset()
    return
}
log.Println("Peer verified successfully via local Groth16 pairing check")
```

#### Mode B: Delegated Swarm Verification (Offloaded)
Send the presentation to a nearby Verification Swarm node over `/p2p-auth/verify/1.0.0` to receive a signed, verifiable `AuthReceipt` ticket:

```go
receipt, err := cl.RequestSwarmTicket(ctx, vp)
if err != nil {
    log.Printf("swarm verification rejected peer: %v", err)
    stream.Reset()
    return
}

fmt.Printf("Verified by Swarm Peer %s (Receipt valid until %d)\n",
    receipt.VerifierPeerId, receipt.ExpiresAt)
```

---

### 5. Manual Enrollment for Existing CA Manifests

If your deployment already possesses an offline ML-DSA-87 signed manifest (from legacy `p2p-anycast` or `p2p-vpn`), enroll directly without a PSK:

```go
vc, err := cl.Enroll(ctx, manifestBytes, caSignatureBytes, "p2p-anycast:ca:manifest:v1")
if err != nil {
    log.Fatalf("manual enrollment failed: %v", err)
}
```
