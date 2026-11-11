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
