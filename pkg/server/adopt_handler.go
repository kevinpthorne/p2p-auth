package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/google/uuid"
	"github.com/kevinpthorne/p2p-auth/pkg/accumulator"
	"github.com/kevinpthorne/p2p-auth/pkg/adopt"
	"github.com/kevinpthorne/p2p-auth/pkg/cred"
	"github.com/kevinpthorne/p2p-auth/pkg/keystore"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
	"github.com/kevinpthorne/p2p-auth/pkg/wire"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
)

// CreatePSK creates and stores a new AdoptionPSKRecord, returning the record and the formatted PSK token.
func (s *AuthServer) CreatePSK(namespace string, mode PSKMode, domainContext string, manifestTemplate []byte, validityDays int, maxUses int, ttl time.Duration, requireHW bool) (*AdoptionPSKRecord, string, error) {
	if namespace == "" {
		namespace = "default"
	}
	if mode == "" {
		mode = PSKModeQueue
	}
	if validityDays <= 0 {
		validityDays = 365
	}
	if maxUses <= 0 {
		maxUses = 1
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	pskID, pskSecret, token, err := adopt.GeneratePSKToken()
	if err != nil {
		return nil, "", err
	}

	now := time.Now().Unix()
	rec := &AdoptionPSKRecord{
		PSKID:               pskID,
		PSKSecret:           pskSecret,
		Namespace:           namespace,
		DomainContext:       cred.ResolveDomainContext(domainContext),
		Mode:                mode,
		ManifestTemplate:    manifestTemplate,
		ValidityDays:        validityDays,
		RequireHardwareTier: requireHW,
		MaxUses:             maxUses,
		UsedCount:           0,
		ExpiresAt:           now + int64(ttl.Seconds()),
		Revoked:             false,
		CreatedAt:           now,
	}

	s.store.mu.Lock()
	s.store.data.AdoptionPSKs[pskID] = rec
	err = s.store.flushLocked()
	s.store.mu.Unlock()
	if err != nil {
		return nil, "", err
	}

	s.events.Publish(fmt.Sprintf("psk_created: id=%s ns=%s mode=%s max_uses=%d", pskID, namespace, mode, maxUses))
	return rec, token, nil
}

// RevokePSK marks an adoption PSK as revoked.
func (s *AuthServer) RevokePSK(pskID string) error {
	s.store.mu.Lock()
	rec, ok := s.store.data.AdoptionPSKs[pskID]
	if !ok {
		s.store.mu.Unlock()
		return fmt.Errorf("PSK %q not found", pskID)
	}
	rec.Revoked = true
	err := s.store.flushLocked()
	s.store.mu.Unlock()
	s.events.Publish(fmt.Sprintf("psk_revoked: id=%s", pskID))
	return err
}

// IssueCredential mints a new VerifiableCredential, signs the opaque manifestPayload with the CA ML-DSA-87 key,
// inserts the leaf commitment into the Poseidon SMT, and rotates the epoch.
func (s *AuthServer) IssueCredential(ctx context.Context, peerID, namespace, subjectID, keystoreTier, domainContext string, manifestPayload []byte, preSignedCASig []byte, validityDays int) (*authpb.VerifiableCredential, error) {
	if validityDays <= 0 {
		validityDays = 365
	}
	if namespace == "" {
		namespace = "default"
	}
	domainCtx := cred.ResolveDomainContext(domainContext)

	renderedPayload := cred.RenderManifestTemplate(manifestPayload, peerID, subjectID)
	caSig := preSignedCASig
	if len(caSig) == 0 {
		var err error
		caSig, err = cred.SignOpaquePayload(s.cfg.CAPrivKey, renderedPayload, domainCtx)
		if err != nil {
			return nil, err
		}
	}

	var secretEl fr.Element
	_, _ = secretEl.SetRandom()
	secretBytes := accumulator.FieldElementToBytes(secretEl)

	claimsCommitment := cred.ComputeClaimsCommitment(renderedPayload)
	now := time.Now().Unix()
	notBefore := now - 60
	notAfter := now + int64(validityDays)*86400

	s.store.mu.Lock()
	serial := s.store.data.NextSerial
	s.store.data.NextSerial++
	leafIdx := s.store.data.NextLeafIndex
	s.store.data.NextLeafIndex++

	leafHash := accumulator.ComputeLeafCommitment(secretBytes, peerID, namespace, claimsCommitment, serial, notBefore, notAfter)
	_, err := s.smt.Insert(leafIdx, leafHash)
	if err != nil {
		s.store.mu.Unlock()
		return nil, err
	}

	nodeRec := &EnrolledNodeRecord{
		PeerID:              peerID,
		Namespace:           namespace,
		SubjectID:           subjectID,
		KeystoreTier:        keystoreTier,
		Serial:              serial,
		LeafIndex:           leafIdx,
		Secret:              secretBytes,
		NotBefore:           notBefore,
		NotAfter:            notAfter,
		ClaimsCommitment:    claimsCommitment,
		ManifestPayload:     renderedPayload,
		ManifestCASignature: caSig,
		DomainContext:       domainCtx,
		Revoked:             false,
		EnrolledAt:          now,
	}
	s.store.data.EnrolledNodes[serial] = nodeRec
	_ = s.store.flushLocked()
	s.store.mu.Unlock()

	eb, err := s.RotateEpoch(ctx)
	if err != nil {
		return nil, err
	}

	siblings, directions, err := s.smt.GetProof(leafIdx)
	if err != nil {
		return nil, err
	}

	vc := &authpb.VerifiableCredential{
		Id:                  "urn:uuid:" + uuid.NewString(),
		Issuer:              "did:p2p:" + s.caKeyID,
		Subject:             "did:p2p:" + peerID,
		Namespace:           namespace,
		SerialNumber:        serial,
		NotBefore:           notBefore,
		NotAfter:            notAfter,
		ManifestPayload:     renderedPayload,
		ClaimsCommitment:    claimsCommitment,
		CredentialSecret:    secretBytes,
		EpochId:             eb.EpochId,
		EpochRoot:           eb.MerkleRoot,
		LeafIndex:           leafIdx,
		MerkleSiblings:      siblings,
		PathDirections:      directions,
		ManifestCaSignature: caSig,
		EpochSignature:      eb.Signature,
		DomainContext:       domainCtx,
	}

	s.events.Publish(fmt.Sprintf("node_enrolled: serial=%d peer=%s ns=%s leaf=%d", serial, peerID, namespace, leafIdx))
	return vc, nil
}

// ProcessAdoptionRequest validates a PSK AdoptionRequest and either auto-approves it (PSKModeAuto)
// or places it in the pending adoption queue (PSKModeQueue).
func (s *AuthServer) ProcessAdoptionRequest(ctx context.Context, req *authpb.AdoptionRequest) (*authpb.AdoptionResponse, error) {
	s.store.mu.Lock()
	pskRec, ok := s.store.data.AdoptionPSKs[req.PskId]
	if !ok {
		s.store.mu.Unlock()
		return nil, errors.New("unknown PSK ID")
	}
	if pskRec.Revoked {
		s.store.mu.Unlock()
		return nil, adopt.ErrPSKRevoked
	}
	now := time.Now()
	if now.Unix() > pskRec.ExpiresAt {
		s.store.mu.Unlock()
		return nil, adopt.ErrPSKExpired
	}
	if pskRec.UsedCount >= pskRec.MaxUses {
		s.store.mu.Unlock()
		return nil, adopt.ErrPSKExhausted
	}
	if pskRec.RequireHardwareTier {
		if req.KeystoreTier != string(keystore.TierTPM2) && req.KeystoreTier != string(keystore.TierSecureEnclave) {
			s.store.mu.Unlock()
			return nil, adopt.ErrHardwareTierRequired
		}
	}

	pskSecret := append([]byte(nil), pskRec.PSKSecret...)
	mode := pskRec.Mode
	ns := req.Namespace
	if ns == "" {
		ns = pskRec.Namespace
	}
	domainCtx := req.DomainContext
	if domainCtx == "" {
		domainCtx = pskRec.DomainContext
	}
	template := pskRec.ManifestTemplate
	if len(template) == 0 {
		template = req.RequestedManifest
	}
	validityDays := pskRec.ValidityDays
	s.store.mu.Unlock()

	if err := adopt.VerifyAdoptionRequest(req, pskSecret, now); err != nil {
		return nil, err
	}

	// Atomically increment PSK usage count
	s.store.mu.Lock()
	pskRec = s.store.data.AdoptionPSKs[req.PskId]
	if pskRec.UsedCount >= pskRec.MaxUses {
		s.store.mu.Unlock()
		return nil, adopt.ErrPSKExhausted
	}
	pskRec.UsedCount++
	_ = s.store.flushLocked()
	s.store.mu.Unlock()

	if mode == PSKModeAuto {
		vc, err := s.IssueCredential(ctx, req.PeerId, ns, req.SubjectId, req.KeystoreTier, domainCtx, template, nil, validityDays)
		if err != nil {
			return nil, err
		}
		s.events.Publish(fmt.Sprintf("adoption_approved: mode=AUTO peer=%s ns=%s", req.PeerId, ns))
		return &authpb.AdoptionResponse{
			State:         authpb.AdoptionState_ADOPTION_APPROVED,
			StatusMessage: "Auto-adopted via scoped PSK",
			Credential:    vc,
		}, nil
	}

	// Queue Mode: store in pending_adoptions
	s.store.mu.Lock()
	existing, exists := s.store.data.PendingAdoptions[req.PeerId]
	if exists && existing.State == authpb.AdoptionState_ADOPTION_APPROVED && existing.Credential != nil {
		s.store.mu.Unlock()
		return &authpb.AdoptionResponse{
			State:         authpb.AdoptionState_ADOPTION_APPROVED,
			StatusMessage: "Approved",
			Credential:    existing.Credential,
		}, nil
	}
	s.store.data.PendingAdoptions[req.PeerId] = &PendingAdoptionRecord{
		PeerID:            req.PeerId,
		Namespace:         ns,
		SubjectID:         req.SubjectId,
		KeystoreTier:      req.KeystoreTier,
		RequestedManifest: template,
		DomainContext:     domainCtx,
		PSKID:             req.PskId,
		CreatedAt:         now.Unix(),
		State:             authpb.AdoptionState_ADOPTION_PENDING,
	}
	_ = s.store.flushLocked()
	s.store.mu.Unlock()

	s.events.Publish(fmt.Sprintf("adoption_pending: peer=%s subject=%s ns=%s tier=%s", req.PeerId, req.SubjectId, ns, req.KeystoreTier))
	return &authpb.AdoptionResponse{
		State:         authpb.AdoptionState_ADOPTION_PENDING,
		StatusMessage: "Pending operator approval",
	}, nil
}

// ApprovePendingNode approves a pending node by Peer ID or Subject ID, mints its VerifiableCredential,
// and notifies any open adoption stream waiting for approval.
func (s *AuthServer) ApprovePendingNode(ctx context.Context, peerOrSubjectID, namespace, domainContext string, manifestPayload []byte) (*authpb.VerifiableCredential, error) {
	s.store.mu.Lock()
	var target *PendingAdoptionRecord
	for _, rec := range s.store.data.PendingAdoptions {
		if rec.PeerID == peerOrSubjectID || (rec.SubjectID != "" && rec.SubjectID == peerOrSubjectID) {
			target = rec
			break
		}
	}
	if target == nil {
		s.store.mu.Unlock()
		return nil, fmt.Errorf("pending adoption record %q not found", peerOrSubjectID)
	}
	peerID := target.PeerID
	subjectID := target.SubjectID
	tier := target.KeystoreTier
	if namespace == "" {
		namespace = target.Namespace
	}
	if domainContext == "" {
		domainContext = target.DomainContext
	}
	if len(manifestPayload) == 0 {
		manifestPayload = target.RequestedManifest
	}
	s.store.mu.Unlock()

	vc, err := s.IssueCredential(ctx, peerID, namespace, subjectID, tier, domainContext, manifestPayload, nil, 365)
	if err != nil {
		return nil, err
	}

	s.store.mu.Lock()
	if rec, ok := s.store.data.PendingAdoptions[peerID]; ok {
		rec.State = authpb.AdoptionState_ADOPTION_APPROVED
		rec.Credential = vc
	}
	delete(s.store.data.PendingAdoptions, peerID)
	_ = s.store.flushLocked()
	s.store.mu.Unlock()

	resp := &authpb.AdoptionResponse{
		State:         authpb.AdoptionState_ADOPTION_APPROVED,
		StatusMessage: "Approved by administrator",
		Credential:    vc,
	}
	s.notifyPendingWaiters(peerID, resp)
	s.events.Publish(fmt.Sprintf("adoption_approved: mode=QUEUE peer=%s ns=%s", peerID, namespace))
	return vc, nil
}

// RejectPendingNode rejects a pending adoption request and notifies any waiting stream.
func (s *AuthServer) RejectPendingNode(peerOrSubjectID string) error {
	s.store.mu.Lock()
	var targetPeerID string
	for _, rec := range s.store.data.PendingAdoptions {
		if rec.PeerID == peerOrSubjectID || (rec.SubjectID != "" && rec.SubjectID == peerOrSubjectID) {
			targetPeerID = rec.PeerID
			break
		}
	}
	if targetPeerID == "" {
		s.store.mu.Unlock()
		return fmt.Errorf("pending adoption %q not found", peerOrSubjectID)
	}
	delete(s.store.data.PendingAdoptions, targetPeerID)
	_ = s.store.flushLocked()
	s.store.mu.Unlock()

	s.notifyPendingWaiters(targetPeerID, &authpb.AdoptionResponse{
		State:         authpb.AdoptionState_ADOPTION_REJECTED,
		StatusMessage: "Rejected by administrator",
	})
	s.events.Publish(fmt.Sprintf("adoption_rejected: peer=%s", targetPeerID))
	return nil
}

func (s *AuthServer) registerPendingWaiter(peerID string) chan *authpb.AdoptionResponse {
	s.waitMu.Lock()
	defer s.waitMu.Unlock()
	ch := make(chan *authpb.AdoptionResponse, 1)
	s.pendingWait[peerID] = append(s.pendingWait[peerID], ch)
	return ch
}

func (s *AuthServer) notifyPendingWaiters(peerID string, resp *authpb.AdoptionResponse) {
	s.waitMu.Lock()
	waiters := s.pendingWait[peerID]
	delete(s.pendingWait, peerID)
	s.waitMu.Unlock()
	for _, ch := range waiters {
		select {
		case ch <- resp:
		default:
		}
	}
}

func (s *AuthServer) handleAdoptStream(stream network.Stream) {
	defer stream.Close()
	var req authpb.AdoptionRequest
	if err := wire.ReadMsg(stream, &req); err != nil {
		return
	}

	ctx := context.Background()
	resp, err := s.ProcessAdoptionRequest(ctx, &req)
	if err != nil {
		_ = wire.WriteMsg(stream, &authpb.AdoptionResponse{
			State:         authpb.AdoptionState_ADOPTION_REJECTED,
			StatusMessage: err.Error(),
		})
		return
	}

	if resp.State == authpb.AdoptionState_ADOPTION_APPROVED || resp.State == authpb.AdoptionState_ADOPTION_REJECTED {
		_ = wire.WriteMsg(stream, resp)
		return
	}

	// Send initial ADOPTION_PENDING status, then block waiting for operator approval on the open stream
	waitCh := s.registerPendingWaiter(req.PeerId)
	if err := wire.WriteMsg(stream, resp); err != nil {
		return
	}

	select {
	case finalResp := <-waitCh:
		_ = wire.WriteMsg(stream, finalResp)
	case <-time.After(10 * time.Minute):
	}
}

// ProcessEnrollmentRequest validates an EnrollmentRequest for a node already holding a CA-signed opaque payload.
func (s *AuthServer) ProcessEnrollmentRequest(ctx context.Context, req *authpb.EnrollmentRequest, remotePubKey ic.PubKey) (*authpb.VerifiableCredential, error) {
	if req == nil {
		return nil, errors.New("EnrollmentRequest is nil")
	}
	if !cred.VerifyOpaquePayload(s.cfg.CAPubKey, req.ManifestPayload, req.DomainContext, req.CaSignature) {
		return nil, cred.ErrInvalidSignature
	}
	if remotePubKey != nil && len(req.PopSignature) > 0 {
		transcript := adopt.BuildEnrollmentTranscript(req)
		if ok, err := remotePubKey.Verify(transcript, req.PopSignature); err != nil || !ok {
			return nil, adopt.ErrInvalidPoPSignature
		}
	}
	return s.IssueCredential(ctx, req.PeerId, req.Namespace, req.PeerId, string(keystore.TierFilesystem), req.DomainContext, req.ManifestPayload, req.CaSignature, 365)
}

func (s *AuthServer) handleEnrollStream(stream network.Stream) {
	defer stream.Close()
	var req authpb.EnrollmentRequest
	if err := wire.ReadMsg(stream, &req); err != nil {
		return
	}
	vc, err := s.ProcessEnrollmentRequest(context.Background(), &req, stream.Conn().RemotePublicKey())
	if err != nil {
		return
	}
	_ = wire.WriteMsg(stream, vc)
}

// RevokeNode revokes an enrolled node by serial number or Peer ID, zeros its leaf in the Poseidon SMT,
// and immediately rotates & broadcasts the new EpochBroadcast.
func (s *AuthServer) RevokeNode(ctx context.Context, serial uint64, peerID string) (*authpb.EpochBroadcast, error) {
	s.store.mu.Lock()
	var revokedAny bool
	for _, node := range s.store.data.EnrolledNodes {
		if (serial > 0 && node.Serial == serial) || (peerID != "" && node.PeerID == peerID) {
			if !node.Revoked {
				node.Revoked = true
				_, _ = s.smt.Revoke(node.LeafIndex)
				revokedAny = true
			}
		}
	}
	if !revokedAny {
		s.store.mu.Unlock()
		return nil, fmt.Errorf("no active credential found matching serial=%d peer=%q", serial, peerID)
	}
	_ = s.store.flushLocked()
	s.store.mu.Unlock()

	eb, err := s.RotateEpoch(ctx)
	if err != nil {
		return nil, err
	}
	s.events.Publish(fmt.Sprintf("node_revoked: serial=%d peer=%s new_epoch=%d", serial, peerID, eb.EpochId))
	return eb, nil
}

// GetUpdatedWitness returns the current SMT Merkle siblings and path directions for an enrolled serial number.
func (s *AuthServer) GetUpdatedWitness(serial uint64) ([][]byte, uint32, error) {
	s.store.mu.RLock()
	node, ok := s.store.data.EnrolledNodes[serial]
	if !ok || node == nil {
		s.store.mu.RUnlock()
		return nil, 0, fmt.Errorf("serial %d not found", serial)
	}
	leafIdx := node.LeafIndex
	s.store.mu.RUnlock()
	return s.smt.GetProof(leafIdx)
}
