package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
)

type PSKMode string

const (
	PSKModeAuto  PSKMode = "AUTO"
	PSKModeQueue PSKMode = "QUEUE"
)

// AdoptionPSKRecord represents a row in the adoption_psks table.
type AdoptionPSKRecord struct {
	PSKID               string  `json:"psk_id"`
	PSKSecret           []byte  `json:"psk_secret"`
	Namespace           string  `json:"namespace"`
	DomainContext       string  `json:"domain_context"`
	Mode                PSKMode `json:"mode"`
	ManifestTemplate    []byte  `json:"manifest_template"`
	ValidityDays        int     `json:"validity_days"`
	RequireHardwareTier bool    `json:"require_hardware_tier"`
	MaxUses             int     `json:"max_uses"`
	UsedCount           int     `json:"used_count"`
	ExpiresAt           int64   `json:"expires_at"`
	Revoked             bool    `json:"revoked"`
	CreatedAt           int64   `json:"created_at"`
}

// PendingAdoptionRecord represents a row in the pending_adoptions table.
type PendingAdoptionRecord struct {
	PeerID            string               `json:"peer_id"`
	Namespace         string               `json:"namespace"`
	SubjectID         string               `json:"subject_id"`
	KeystoreTier      string               `json:"keystore_tier"`
	RequestedManifest []byte               `json:"requested_manifest"`
	DomainContext     string               `json:"domain_context"`
	PSKID             string               `json:"psk_id"`
	CreatedAt         int64                `json:"created_at"`
	State             authpb.AdoptionState `json:"state"`
	Credential        *authpb.VerifiableCredential `json:"credential,omitempty"`
}

// EnrolledNodeRecord represents a row in the enrolled_nodes table.
type EnrolledNodeRecord struct {
	PeerID              string `json:"peer_id"`
	Namespace           string `json:"namespace"`
	SubjectID           string `json:"subject_id"`
	KeystoreTier        string `json:"keystore_tier"`
	Serial              uint64 `json:"serial"`
	LeafIndex           uint32 `json:"leaf_index"`
	Secret              []byte `json:"secret"`
	NotBefore           int64  `json:"not_before"`
	NotAfter            int64  `json:"not_after"`
	ClaimsCommitment    []byte `json:"claims_commitment"`
	ManifestPayload     []byte `json:"manifest_payload"`
	ManifestCASignature []byte `json:"manifest_ca_signature"`
	DomainContext       string `json:"domain_context"`
	Revoked             bool   `json:"revoked"`
	EnrolledAt          int64  `json:"enrolled_at"`
}

// EpochRecord represents a row in the epochs table.
type EpochRecord struct {
	EpochID           uint64 `json:"epoch_id"`
	Root              []byte `json:"root"`
	Timestamp         int64  `json:"timestamp"`
	ValidUntil        int64  `json:"valid_until"`
	ActiveCredentials uint32 `json:"active_credentials"`
	CAPubKey          []byte `json:"ca_pubkey"`
	Signature         []byte `json:"signature"`
}

type dbSnapshot struct {
	NextSerial       uint64                            `json:"next_serial"`
	NextLeafIndex    uint32                            `json:"next_leaf_index"`
	CurrentEpochID   uint64                            `json:"current_epoch_id"`
	AdoptionPSKs     map[string]*AdoptionPSKRecord     `json:"adoption_psks"`
	PendingAdoptions map[string]*PendingAdoptionRecord `json:"pending_adoptions"`
	EnrolledNodes    map[uint64]*EnrolledNodeRecord    `json:"enrolled_nodes"`
	Epochs           map[uint64]*EpochRecord           `json:"epochs"`
}

// Store is an atomic, crash-safe persistent state database for p2p-auth-server.
type Store struct {
	mu   sync.RWMutex
	path string
	data dbSnapshot
}

// OpenStore opens or creates the persistent auth.db file at path.
func OpenStore(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: dbSnapshot{
			NextSerial:       1,
			NextLeafIndex:    0,
			CurrentEpochID:   0,
			AdoptionPSKs:     make(map[string]*AdoptionPSKRecord),
			PendingAdoptions: make(map[string]*PendingAdoptionRecord),
			EnrolledNodes:    make(map[uint64]*EnrolledNodeRecord),
			Epochs:           make(map[uint64]*EpochRecord),
		},
	}

	if path == "" {
		return s, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := s.flushLocked(); err != nil {
				return nil, err
			}
			return s, nil
		}
		return nil, fmt.Errorf("reading store %s: %w", path, err)
	}

	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("decoding store %s: %w", path, err)
		}
		if s.data.AdoptionPSKs == nil {
			s.data.AdoptionPSKs = make(map[string]*AdoptionPSKRecord)
		}
		if s.data.PendingAdoptions == nil {
			s.data.PendingAdoptions = make(map[string]*PendingAdoptionRecord)
		}
		if s.data.EnrolledNodes == nil {
			s.data.EnrolledNodes = make(map[uint64]*EnrolledNodeRecord)
		}
		if s.data.Epochs == nil {
			s.data.Epochs = make(map[uint64]*EpochRecord)
		}
	}

	return s, nil
}

func (s *Store) flushLocked() error {
	if s.path == "" {
		return nil
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(&s.data, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}
