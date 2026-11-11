package adopt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kevinpthorne/p2p-auth/pkg/keystore"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	AdoptionDomainContext = "p2p-auth:adopt:v1"
	EnrollDomainContext   = "p2p-auth:enroll:v1"
	PSKTokenPrefix        = "p2p_psk_"
	MaxTimestampSkewSecs  = 300
)

var (
	ErrInvalidPSKToken      = errors.New("invalid PSK token format (expected p2p_psk_<id>_<secret_hex>)")
	ErrInvalidPSKHMAC       = errors.New("PSK HMAC verification failed")
	ErrInvalidPoPSignature  = errors.New("hardware key Proof-of-Possession signature verification failed")
	ErrPeerIDMismatch       = errors.New("Peer ID does not match public key in AdoptionRequest")
	ErrTimestampOutOfWindow = errors.New("AdoptionRequest timestamp outside allowed 300s skew window")
	ErrPSKExpired           = errors.New("adoption PSK has expired")
	ErrPSKRevoked           = errors.New("adoption PSK has been revoked")
	ErrPSKExhausted         = errors.New("adoption PSK has reached max_uses")
	ErrHardwareTierRequired = errors.New("adoption PSK requires hardware keystore tier (TPM2.0 or AppleSecureEnclave)")
)

// GeneratePSKToken mints a new PSK ID (8 hex chars) and 32-byte secret, returning (pskID, pskSecret, formattedToken).
func GeneratePSKToken() (string, []byte, string, error) {
	idBytes := make([]byte, 4)
	if _, err := rand.Read(idBytes); err != nil {
		return "", nil, "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", nil, "", err
	}
	pskID := hex.EncodeToString(idBytes)
	secretHex := hex.EncodeToString(secret)
	token := fmt.Sprintf("%s%s_%s", PSKTokenPrefix, pskID, secretHex)
	return pskID, secret, token, nil
}

// ParsePSKToken parses a formatted token string "p2p_psk_<id>_<secret_hex>" into (pskID, pskSecret).
func ParsePSKToken(token string) (string, []byte, error) {
	trimmed := strings.TrimSpace(token)
	if !strings.HasPrefix(trimmed, PSKTokenPrefix) {
		return "", nil, ErrInvalidPSKToken
	}
	rest := strings.TrimPrefix(trimmed, PSKTokenPrefix)
	parts := strings.SplitN(rest, "_", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", nil, ErrInvalidPSKToken
	}
	secret, err := hex.DecodeString(parts[1])
	if err != nil || len(secret) == 0 {
		return "", nil, ErrInvalidPSKToken
	}
	return parts[0], secret, nil
}

func appendLenPrefixed(buf []byte, data []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	buf = append(buf, lenBuf[:]...)
	return append(buf, data...)
}

// BuildAdoptionTranscript builds the canonical domain-separated byte transcript for an AdoptionRequest:
// ("p2p-auth:adopt:v1" || psk_id || namespace || peer_id || pub_key || keystore_tier || subject_id || requested_manifest || domain_context || timestamp || nonce)
func BuildAdoptionTranscript(req *authpb.AdoptionRequest) []byte {
	buf := make([]byte, 0, 256+len(req.RequestedManifest))
	buf = appendLenPrefixed(buf, []byte(AdoptionDomainContext))
	buf = appendLenPrefixed(buf, []byte(req.PskId))
	buf = appendLenPrefixed(buf, []byte(req.Namespace))
	buf = appendLenPrefixed(buf, []byte(req.PeerId))
	buf = appendLenPrefixed(buf, req.PubKey)
	buf = appendLenPrefixed(buf, []byte(req.KeystoreTier))
	buf = appendLenPrefixed(buf, []byte(req.SubjectId))
	buf = appendLenPrefixed(buf, req.RequestedManifest)
	buf = appendLenPrefixed(buf, []byte(req.DomainContext))
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(req.Timestamp))
	buf = append(buf, tsBuf[:]...)
	buf = appendLenPrefixed(buf, req.Nonce)
	return buf
}

// SignAdoptionRequest populates PubKey, PeerId, KeystoreTier, Timestamp, Nonce, PopSignature, PskId, and PskHmac on req.
func SignAdoptionRequest(req *authpb.AdoptionRequest, idKey *keystore.IdentityKey, pskToken string) error {
	pskID, pskSecret, err := ParsePSKToken(pskToken)
	if err != nil {
		return err
	}

	pubBytes, err := ic.MarshalPublicKey(idKey.Libp2pPrivKey().GetPublic())
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}

	req.PskId = pskID
	req.PeerId = idKey.PeerID().String()
	req.PubKey = pubBytes
	if req.KeystoreTier == "" {
		req.KeystoreTier = string(idKey.Tier())
	}
	if req.Timestamp == 0 {
		req.Timestamp = time.Now().Unix()
	}
	if len(req.Nonce) == 0 {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("generating adoption nonce: %w", err)
		}
		req.Nonce = nonce
	}

	transcript := BuildAdoptionTranscript(req)

	popSig, err := idKey.Libp2pPrivKey().Sign(transcript)
	if err != nil {
		return fmt.Errorf("signing adoption transcript with hardware key: %w", err)
	}
	req.PopSignature = popSig

	mac := hmac.New(sha256.New, pskSecret)
	mac.Write(transcript)
	req.PskHmac = mac.Sum(nil)
	return nil
}

// VerifyAdoptionRequest validates the timestamp window, Peer ID binding, hardware key Proof-of-Possession signature,
// and constant-time PSK HMAC on an incoming AdoptionRequest.
func VerifyAdoptionRequest(req *authpb.AdoptionRequest, pskSecret []byte, now time.Time) error {
	if req == nil {
		return errors.New("AdoptionRequest is nil")
	}
	diff := now.Unix() - req.Timestamp
	if diff < -MaxTimestampSkewSecs || diff > MaxTimestampSkewSecs {
		return ErrTimestampOutOfWindow
	}

	pubKey, err := ic.UnmarshalPublicKey(req.PubKey)
	if err != nil {
		return fmt.Errorf("unmarshaling node public key: %w", err)
	}
	derivedPeerID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("deriving Peer ID from public key: %w", err)
	}
	if derivedPeerID.String() != req.PeerId {
		return ErrPeerIDMismatch
	}

	transcript := BuildAdoptionTranscript(req)

	// 1. Constant-time PSK HMAC check
	mac := hmac.New(sha256.New, pskSecret)
	mac.Write(transcript)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(expectedMAC, req.PskHmac) {
		return ErrInvalidPSKHMAC
	}

	// 2. Hardware key Proof-of-Possession signature check
	ok, err := pubKey.Verify(transcript, req.PopSignature)
	if err != nil || !ok {
		return ErrInvalidPoPSignature
	}

	return nil
}

// BuildEnrollmentTranscript builds the canonical transcript for EnrollmentRequest Proof-of-Possession.
func BuildEnrollmentTranscript(req *authpb.EnrollmentRequest) []byte {
	payloadHash := sha256.Sum256(req.ManifestPayload)
	buf := make([]byte, 0, 128)
	buf = appendLenPrefixed(buf, []byte(EnrollDomainContext))
	buf = appendLenPrefixed(buf, []byte(req.Namespace))
	buf = appendLenPrefixed(buf, []byte(req.PeerId))
	buf = appendLenPrefixed(buf, payloadHash[:])
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(req.Timestamp))
	buf = append(buf, tsBuf[:]...)
	return buf
}
