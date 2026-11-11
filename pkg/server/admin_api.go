package server

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/kevinpthorne/p2p-auth/gui"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
	"google.golang.org/protobuf/proto"
)

func (s *AuthServer) checkAdminAuth(r *http.Request) bool {
	expected := []byte(s.cfg.AdminToken)
	if len(expected) == 0 {
		return false
	}
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		tok := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(tok), expected) == 1 {
			return true
		}
	}
	if c, err := r.Cookie("p2p_auth_session"); err == nil {
		if subtle.ConstantTimeCompare([]byte(c.Value), expected) == 1 {
			return true
		}
	}
	if qTok := r.URL.Query().Get("token"); qTok != "" {
		if subtle.ConstantTimeCompare([]byte(qTok), expected) == 1 {
			return true
		}
	}
	return false
}

func (s *AuthServer) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.checkAdminAuth(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *AuthServer) registerHTTPRoutes(mux *http.ServeMux) {
	// Machine-to-Machine Node HTTP REST Endpoints
	mux.HandleFunc("/v1/adopt", s.handleHTTPV1Adopt)
	mux.HandleFunc("/v1/enroll", s.handleHTTPV1Enroll)
	mux.HandleFunc("/v1/epoch/current", s.handleHTTPV1EpochCurrent)

	// Admin API Endpoints
	mux.HandleFunc("/api/admin/login", s.handleAdminLogin)
	mux.HandleFunc("/api/admin/status", s.requireAdmin(s.handleAdminStatus))
	mux.HandleFunc("/api/admin/epoch/rotate", s.requireAdmin(s.handleAdminEpochRotate))
	mux.HandleFunc("/api/admin/psks", s.requireAdmin(s.handleAdminPSKs))
	mux.HandleFunc("/api/admin/psks/", s.requireAdmin(s.handleAdminPSKDelete))
	mux.HandleFunc("/api/admin/adopt/pending", s.requireAdmin(s.handleAdminAdoptPending))
	mux.HandleFunc("/api/admin/adopt/approve", s.requireAdmin(s.handleAdminAdoptApprove))
	mux.HandleFunc("/api/admin/adopt/reject", s.requireAdmin(s.handleAdminAdoptReject))
	mux.HandleFunc("/api/admin/nodes", s.requireAdmin(s.handleAdminNodes))
	mux.HandleFunc("/api/admin/nodes/enroll", s.requireAdmin(s.handleAdminNodesEnroll))
	mux.HandleFunc("/api/admin/revoke", s.requireAdmin(s.handleAdminRevoke))
	mux.HandleFunc("/api/admin/events", s.requireAdmin(s.handleAdminEventsSSE))

	// Embedded Web Admin UI
	if !s.cfg.DisableUI {
		fileServer := http.FileServer(http.FS(gui.StaticFiles))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				data, err := fs.ReadFile(gui.StaticFiles, "index.html")
				if err != nil {
					http.Error(w, "UI not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(data)
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	}
}

func (s *AuthServer) handleHTTPV1Adopt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req authpb.AdoptionRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.ProcessAdoptionRequest(r.Context(), &req)
	if err != nil {
		resp = &authpb.AdoptionResponse{
			State:         authpb.AdoptionState_ADOPTION_REJECTED,
			StatusMessage: err.Error(),
		}
	}
	out, _ := proto.Marshal(resp)
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(out)
}

func (s *AuthServer) handleHTTPV1Enroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req authpb.EnrollmentRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	vc, err := s.ProcessEnrollmentRequest(r.Context(), &req, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	out, _ := proto.Marshal(vc)
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(out)
}

func (s *AuthServer) handleHTTPV1EpochCurrent(w http.ResponseWriter, r *http.Request) {
	eb := s.CurrentEpoch()
	if eb == nil {
		http.Error(w, "no epoch", http.StatusNotFound)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "application/x-protobuf") {
		out, _ := proto.Marshal(eb)
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(out)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"epoch_id":           eb.EpochId,
		"merkle_root":        hex.EncodeToString(eb.MerkleRoot),
		"timestamp":          eb.Timestamp,
		"valid_until":        eb.ValidUntil,
		"active_credentials": eb.ActiveCredentials,
	})
}

func (s *AuthServer) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.Token)), []byte(s.cfg.AdminToken)) != 1 {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "p2p_auth_session",
		Value:    s.cfg.AdminToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   12 * 3600,
	})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

func (s *AuthServer) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	s.store.mu.RLock()
	epochID := s.store.data.CurrentEpochID
	pendingCount := len(s.store.data.PendingAdoptions)
	pskCount := 0
	for _, p := range s.store.data.AdoptionPSKs {
		if !p.Revoked {
			pskCount++
		}
	}
	s.store.mu.RUnlock()

	rootHex := hex.EncodeToString(s.smt.Root())
	activeCount := s.smt.ActiveLeafCount()
	swarmPeers := len(s.host.Network().Peers())

	writeJSON(w, http.StatusOK, map[string]any{
		"epoch_id":                epochID,
		"merkle_root":             rootHex,
		"active_nodes_count":      activeCount,
		"pending_adoptions_count": pendingCount,
		"active_psks_count":       pskCount,
		"ca_key_id":               s.caKeyID,
		"swarm_peers_count":       swarmPeers,
		"server_multiaddr":        s.Multiaddr(),
	})
}

func (s *AuthServer) handleAdminEpochRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	eb, err := s.RotateEpoch(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"epoch_id":    eb.EpochId,
		"merkle_root": hex.EncodeToString(eb.MerkleRoot),
	})
}

func (s *AuthServer) handleAdminPSKs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.store.mu.RLock()
		list := make([]map[string]any, 0, len(s.store.data.AdoptionPSKs))
		for _, p := range s.store.data.AdoptionPSKs {
			list = append(list, map[string]any{
				"psk_id":                p.PSKID,
				"namespace":             p.Namespace,
				"domain_context":        p.DomainContext,
				"mode":                  p.Mode,
				"manifest_template":     string(p.ManifestTemplate),
				"require_hardware_tier": p.RequireHardwareTier,
				"max_uses":              p.MaxUses,
				"used_count":            p.UsedCount,
				"expires_at":            p.ExpiresAt,
				"revoked":               p.Revoked,
			})
		}
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, list)

	case http.MethodPost:
		var req struct {
			Namespace           string `json:"namespace"`
			Mode                string `json:"mode"`
			DomainContext       string `json:"domain_context"`
			ManifestTemplate    string `json:"manifest_template"`
			ValidityDays        int    `json:"validity_days"`
			MaxUses             int    `json:"max_uses"`
			TTLHours            int    `json:"ttl_hours"`
			RequireHardwareTier bool   `json:"require_hardware_tier"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ttl := time.Duration(req.TTLHours) * time.Hour
		if ttl <= 0 {
			ttl = 24 * time.Hour
		}
		rec, token, err := s.CreatePSK(
			req.Namespace,
			PSKMode(strings.ToUpper(req.Mode)),
			req.DomainContext,
			[]byte(req.ManifestTemplate),
			req.ValidityDays,
			req.MaxUses,
			ttl,
			req.RequireHardwareTier,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"psk_id": rec.PSKID,
			"token":  token,
			"mode":   rec.Mode,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *AuthServer) handleAdminPSKDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/psks/")
	if err := s.RevokePSK(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "psk_id": id})
}

func (s *AuthServer) handleAdminAdoptPending(w http.ResponseWriter, r *http.Request) {
	s.store.mu.RLock()
	list := make([]map[string]any, 0, len(s.store.data.PendingAdoptions))
	for _, p := range s.store.data.PendingAdoptions {
		if p.State == authpb.AdoptionState_ADOPTION_PENDING {
			list = append(list, map[string]any{
				"peer_id":                 p.PeerID,
				"namespace":               p.Namespace,
				"subject_id":              p.SubjectID,
				"keystore_tier":           p.KeystoreTier,
				"requested_manifest_text": string(p.RequestedManifest),
				"domain_context":          p.DomainContext,
				"psk_id":                  p.PSKID,
				"created_at":              p.CreatedAt,
			})
		}
	}
	s.store.mu.RUnlock()
	writeJSON(w, http.StatusOK, list)
}

func (s *AuthServer) handleAdminAdoptApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PeerID          string `json:"peer_id"`
		Namespace       string `json:"namespace"`
		DomainContext   string `json:"domain_context"`
		ManifestPayload string `json:"manifest_payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	vc, err := s.ApprovePendingNode(r.Context(), req.PeerID, req.Namespace, req.DomainContext, []byte(req.ManifestPayload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"approved":          true,
		"serial_number":     vc.SerialNumber,
		"peer_id":           req.PeerID,
		"namespace":         vc.Namespace,
		"epoch_id":          vc.EpochId,
		"claims_commitment": hex.EncodeToString(vc.ClaimsCommitment),
	})
}

func (s *AuthServer) handleAdminAdoptReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PeerID string `json:"peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.RejectPendingNode(req.PeerID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rejected": true})
}

func (s *AuthServer) handleAdminNodes(w http.ResponseWriter, r *http.Request) {
	nsFilter := r.URL.Query().Get("namespace")
	statusFilter := r.URL.Query().Get("status")

	s.store.mu.RLock()
	list := make([]map[string]any, 0, len(s.store.data.EnrolledNodes))
	for _, n := range s.store.data.EnrolledNodes {
		if nsFilter != "" && n.Namespace != nsFilter {
			continue
		}
		if statusFilter == "active" && n.Revoked {
			continue
		}
		if statusFilter == "revoked" && !n.Revoked {
			continue
		}
		list = append(list, map[string]any{
			"serial":                n.Serial,
			"peer_id":               n.PeerID,
			"namespace":             n.Namespace,
			"subject_id":            n.SubjectID,
			"keystore_tier":         n.KeystoreTier,
			"leaf_index":            n.LeafIndex,
			"not_before":            n.NotBefore,
			"not_after":             n.NotAfter,
			"claims_commitment_hex": hex.EncodeToString(n.ClaimsCommitment),
			"manifest_text":         string(n.ManifestPayload),
			"domain_context":        n.DomainContext,
			"revoked":               n.Revoked,
		})
	}
	s.store.mu.RUnlock()
	writeJSON(w, http.StatusOK, list)
}

func (s *AuthServer) handleAdminNodesEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PeerID          string `json:"peer_id"`
		SubjectID       string `json:"subject_id"`
		Namespace       string `json:"namespace"`
		DomainContext   string `json:"domain_context"`
		ManifestPayload string `json:"manifest_payload"`
		ValidityDays    int    `json:"validity_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	vc, err := s.IssueCredential(r.Context(), req.PeerID, req.Namespace, req.SubjectID, "ManualAdmin", req.DomainContext, []byte(req.ManifestPayload), nil, req.ValidityDays)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"serial_number":     vc.SerialNumber,
		"peer_id":           req.PeerID,
		"namespace":         vc.Namespace,
		"epoch_id":          vc.EpochId,
		"claims_commitment": hex.EncodeToString(vc.ClaimsCommitment),
	})
}

func (s *AuthServer) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Serial uint64 `json:"serial"`
		PeerID string `json:"peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	eb, err := s.RevokeNode(r.Context(), req.Serial, req.PeerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revoked":     true,
		"new_epoch":   eb.EpochId,
		"merkle_root": hex.EncodeToString(eb.MerkleRoot),
	})
}

func (s *AuthServer) handleAdminEventsSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := s.events.Subscribe()
	defer s.events.Unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			_, _ = w.Write([]byte("data: " + msg + "\n\n"))
			flusher.Flush()
		}
	}
}
