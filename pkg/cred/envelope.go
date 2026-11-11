package cred

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/kevinpthorne/p2p-auth/pkg/accumulator"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
)

type PublicKeyAlias = mldsa87.PublicKey
type PrivateKeyAlias = mldsa87.PrivateKey

const (
	DefaultDomainContext = "p2p-auth:manifest:v1"
	EpochDomainContext   = "p2p-auth:epoch:v1"

	PublicKeyPEMType  = "ML-DSA-87 PUBLIC KEY"
	PrivateKeyPEMType = "ML-DSA-87 PRIVATE KEY"
)

var (
	ErrInvalidSignature = errors.New("ML-DSA-87 signature verification failed")
	ErrEmptyPayload     = errors.New("opaque manifest payload cannot be empty")
)

// GenerateCAKeyPair generates a FIPS 204 ML-DSA-87 CA keypair.
func GenerateCAKeyPair() (*mldsa87.PublicKey, *mldsa87.PrivateKey, error) {
	return mldsa87.GenerateKey(rand.Reader)
}

// ComputeCAKeyID returns the hex-encoded SHA-256 fingerprint of an ML-DSA-87 public key.
func ComputeCAKeyID(pub *mldsa87.PublicKey) string {
	b := pub.Bytes()
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// SaveCAKeyPair writes the ML-DSA-87 private and public keys as PEM files.
func SaveCAKeyPair(privPath, pubPath string, pub *mldsa87.PublicKey, priv *mldsa87.PrivateKey) error {
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PrivateKeyPEMType,
		Bytes: priv.Bytes(),
	})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return fmt.Errorf("writing CA private key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PublicKeyPEMType,
		Bytes: pub.Bytes(),
	})
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return fmt.Errorf("writing CA public key: %w", err)
	}
	return nil
}

// LoadCAPublicKey loads an ML-DSA-87 public key from PEM or raw bytes on disk.
func LoadCAPublicKey(path string) (*mldsa87.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA public key %s: %w", path, err)
	}
	return ParseCAPublicKey(data)
}

// ParseCAPublicKey parses an ML-DSA-87 public key from PEM or raw 2592-byte slice.
func ParseCAPublicKey(data []byte) (*mldsa87.PublicKey, error) {
	raw := data
	if block, _ := pem.Decode(data); block != nil {
		raw = block.Bytes
	}
	if len(raw) != mldsa87.PublicKeySize {
		return nil, fmt.Errorf("invalid ML-DSA-87 public key size: got %d, want %d", len(raw), mldsa87.PublicKeySize)
	}
	var pk mldsa87.PublicKey
	if err := pk.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("unmarshaling ML-DSA-87 public key: %w", err)
	}
	return &pk, nil
}

// LoadCAPrivateKey loads an ML-DSA-87 private key from PEM or raw bytes on disk.
func LoadCAPrivateKey(path string) (*mldsa87.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA private key %s: %w", path, err)
	}
	raw := data
	if block, _ := pem.Decode(data); block != nil {
		raw = block.Bytes
	}
	if len(raw) != mldsa87.PrivateKeySize {
		return nil, fmt.Errorf("invalid ML-DSA-87 private key size: got %d, want %d", len(raw), mldsa87.PrivateKeySize)
	}
	var sk mldsa87.PrivateKey
	if err := sk.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("unmarshaling ML-DSA-87 private key: %w", err)
	}
	return &sk, nil
}

// ResolveDomainContext returns the normalized domain context, defaulting to DefaultDomainContext.
func ResolveDomainContext(domainContext string) string {
	trimmed := strings.TrimSpace(domainContext)
	if trimmed == "" {
		return DefaultDomainContext
	}
	return trimmed
}

// SignOpaquePayload signs arbitrary application manifest/claims bytes with ML-DSA-87 under domainContext.
func SignOpaquePayload(sk *mldsa87.PrivateKey, payload []byte, domainContext string) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("CA private key is nil")
	}
	if len(payload) == 0 {
		return nil, ErrEmptyPayload
	}
	ctx := ResolveDomainContext(domainContext)
	if len(ctx) > 255 {
		return nil, fmt.Errorf("domain context exceeds 255 bytes: %d", len(ctx))
	}
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(sk, payload, []byte(ctx), false, sig); err != nil {
		return nil, fmt.Errorf("signing opaque payload with ML-DSA-87: %w", err)
	}
	return sig, nil
}

// VerifyOpaquePayload verifies an ML-DSA-87 signature over opaque application bytes under domainContext.
func VerifyOpaquePayload(pk *mldsa87.PublicKey, payload []byte, domainContext string, sig []byte) bool {
	if pk == nil || len(payload) == 0 {
		return false
	}
	rawSig := sig
	if block, _ := pem.Decode(sig); block != nil {
		rawSig = block.Bytes
	}
	if len(rawSig) != mldsa87.SignatureSize {
		return false
	}
	ctx := ResolveDomainContext(domainContext)
	if len(ctx) > 255 {
		return false
	}
	return mldsa87.Verify(pk, payload, []byte(ctx), rawSig)
}

// RenderManifestTemplate substitutes optional {{PEER_ID}} and {{SUBJECT_ID}} placeholders
// in an opaque manifest template without inspecting or parsing the underlying schema.
func RenderManifestTemplate(templateBytes []byte, peerID string, subjectID string) []byte {
	if len(templateBytes) == 0 {
		return []byte(peerID)
	}
	s := string(templateBytes)
	s = strings.ReplaceAll(s, "{{PEER_ID}}", peerID)
	s = strings.ReplaceAll(s, "{{SUBJECT_ID}}", subjectID)
	return []byte(s)
}

// ComputeClaimsCommitment computes the 32-byte BN254 Poseidon sponge commitment over opaque manifest bytes.
func ComputeClaimsCommitment(manifestPayload []byte) []byte {
	return accumulator.PoseidonBytes(manifestPayload)
}

func buildEpochTranscript(eb *authpb.EpochBroadcast) []byte {
	buf := make([]byte, 0, 8+32+8+8+4)
	var tmp8 [8]byte
	var tmp4 [4]byte
	binary.BigEndian.PutUint64(tmp8[:], eb.EpochId)
	buf = append(buf, tmp8[:]...)
	buf = append(buf, eb.MerkleRoot...)
	binary.BigEndian.PutUint64(tmp8[:], uint64(eb.Timestamp))
	buf = append(buf, tmp8[:]...)
	binary.BigEndian.PutUint64(tmp8[:], uint64(eb.ValidUntil))
	buf = append(buf, tmp8[:]...)
	binary.BigEndian.PutUint32(tmp4[:], eb.ActiveCredentials)
	buf = append(buf, tmp4[:]...)
	return buf
}

// SignEpochBroadcast signs an EpochBroadcast header with the CA ML-DSA-87 private key.
func SignEpochBroadcast(sk *mldsa87.PrivateKey, pub *mldsa87.PublicKey, eb *authpb.EpochBroadcast) error {
	eb.CaPubkey = pub.Bytes()
	sig := make([]byte, mldsa87.SignatureSize)
	transcript := buildEpochTranscript(eb)
	if err := mldsa87.SignTo(sk, transcript, []byte(EpochDomainContext), false, sig); err != nil {
		return fmt.Errorf("signing EpochBroadcast: %w", err)
	}
	eb.Signature = sig
	return nil
}

// VerifyEpochBroadcast verifies the CA ML-DSA-87 signature on an EpochBroadcast message.
func VerifyEpochBroadcast(trustedPub *mldsa87.PublicKey, eb *authpb.EpochBroadcast) bool {
	if eb == nil || len(eb.Signature) != mldsa87.SignatureSize {
		return false
	}
	pk := trustedPub
	if pk == nil && len(eb.CaPubkey) == mldsa87.PublicKeySize {
		parsed, err := ParseCAPublicKey(eb.CaPubkey)
		if err != nil {
			return false
		}
		pk = parsed
	}
	if pk == nil {
		return false
	}
	transcript := buildEpochTranscript(eb)
	return mldsa87.Verify(pk, transcript, []byte(EpochDomainContext), eb.Signature)
}
