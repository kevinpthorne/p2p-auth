package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/kevinpthorne/p2p-auth/pkg/accumulator"
	"github.com/kevinpthorne/p2p-auth/pkg/cred"
	"github.com/kevinpthorne/p2p-auth/pkg/keystore"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
	"github.com/kevinpthorne/p2p-auth/pkg/wire"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

// Config configures the Central Auth Server (p2p-auth-server).
type Config struct {
	StorePath     string
	CAPubKey      *mldsa87.PublicKey
	CAPrivKey     *mldsa87.PrivateKey
	HostIdentity  *keystore.IdentityKey
	P2PListenAddr string // e.g. "/ip4/127.0.0.1/tcp/0"
	HTTPAddr      string // e.g. "127.0.0.1:8080"
	AdminToken    string
	EpochDuration time.Duration
	DisableUI     bool
	TLSCertFile   string
	TLSKeyFile    string
}

// EventBroker broadcasts real-time audit events to SSE subscribers in the Web Admin UI.
type EventBroker struct {
	mu          sync.Mutex
	subscribers map[chan string]struct{}
	history     []string
}

func newEventBroker() *EventBroker {
	return &EventBroker{
		subscribers: make(map[chan string]struct{}),
		history:     make([]string, 0, 128),
	}
}

func (b *EventBroker) Publish(event string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.history) >= 200 {
		b.history = b.history[1:]
	}
	b.history = append(b.history, event)
	for ch := range b.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

func (b *EventBroker) Subscribe() chan string {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan string, 64)
	for _, msg := range b.history {
		ch <- msg
	}
	b.subscribers[ch] = struct{}{}
	return ch
}

func (b *EventBroker) Unsubscribe(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subscribers, ch)
	close(ch)
}

// AuthServer is the application-agnostic Central Auth & ZK-VC Issuance Server.
type AuthServer struct {
	cfg        Config
	store      *Store
	smt        *accumulator.SMT
	caKeyID    string
	host       host.Host
	ps         *pubsub.PubSub
	epochTopic *pubsub.Topic
	httpSrv    *http.Server
	httpAddr   string
	events     *EventBroker

	waitMu      sync.Mutex
	pendingWait map[string][]chan *authpb.AdoptionResponse

	cancel context.CancelFunc
}

// NewAuthServer initializes the AuthServer, reconstructs the Poseidon Sparse Merkle Tree
// from the persistent Store, and sets up the libp2p host and GossipSub epoch publisher.
func NewAuthServer(ctx context.Context, cfg Config) (*AuthServer, error) {
	if cfg.CAPubKey == nil || cfg.CAPrivKey == nil {
		var err error
		cfg.CAPubKey, cfg.CAPrivKey, err = cred.GenerateCAKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generating CA keypair: %w", err)
		}
	}
	if cfg.HostIdentity == nil {
		var err error
		cfg.HostIdentity, err = keystore.GenerateEphemeralIdentity()
		if err != nil {
			return nil, fmt.Errorf("generating host identity: %w", err)
		}
	}
	if cfg.EpochDuration <= 0 {
		cfg.EpochDuration = time.Hour
	}
	if cfg.AdminToken == "" {
		tokBytes := make([]byte, 16)
		_, _ = rand.Read(tokBytes)
		cfg.AdminToken = hex.EncodeToString(tokBytes)
		log.Printf("[p2p-auth-server] Generated Admin Token: %s", cfg.AdminToken)
	}
	if cfg.P2PListenAddr == "" {
		cfg.P2PListenAddr = "/ip4/127.0.0.1/tcp/0"
	}

	store, err := OpenStore(cfg.StorePath)
	if err != nil {
		return nil, fmt.Errorf("opening store: %w", err)
	}

	smt, err := accumulator.NewSMT(accumulator.DefaultSMTDepth)
	if err != nil {
		return nil, fmt.Errorf("initializing SMT: %w", err)
	}

	// Rebuild SMT from non-revoked enrolled nodes in store
	store.mu.RLock()
	for _, node := range store.data.EnrolledNodes {
		if !node.Revoked {
			leaf := accumulator.ComputeLeafCommitment(
				node.Secret,
				node.PeerID,
				node.Namespace,
				node.ClaimsCommitment,
				node.Serial,
				node.NotBefore,
				node.NotAfter,
			)
			_, _ = smt.Insert(node.LeafIndex, leaf)
		}
	}
	store.mu.RUnlock()

	h, err := libp2p.New(
		libp2p.Identity(cfg.HostIdentity.Libp2pPrivKey()),
		libp2p.ListenAddrStrings(cfg.P2PListenAddr),
	)
	if err != nil {
		return nil, fmt.Errorf("creating libp2p host: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	ps, err := pubsub.NewGossipSub(runCtx, h)
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, fmt.Errorf("creating GossipSub: %w", err)
	}

	topic, err := ps.Join(wire.TopicEpoch)
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, fmt.Errorf("joining epoch topic: %w", err)
	}

	srv := &AuthServer{
		cfg:         cfg,
		store:       store,
		smt:         smt,
		caKeyID:     cred.ComputeCAKeyID(cfg.CAPubKey),
		host:        h,
		ps:          ps,
		epochTopic:  topic,
		events:      newEventBroker(),
		pendingWait: make(map[string][]chan *authpb.AdoptionResponse),
		cancel:      cancel,
	}

	// Register libp2p stream handlers
	h.SetStreamHandler(wire.ProtocolAdopt, srv.handleAdoptStream)
	h.SetStreamHandler(wire.ProtocolEnroll, srv.handleEnrollStream)
	h.SetStreamHandler(wire.ProtocolSync, srv.handleSyncStream)

	// Ensure initial epoch exists
	if srv.CurrentEpoch() == nil {
		if _, err := srv.RotateEpoch(runCtx); err != nil {
			cancel()
			_ = h.Close()
			return nil, fmt.Errorf("initializing epoch 1: %w", err)
		}
	}

	// Start periodic epoch rotation loop
	go srv.epochRotationLoop(runCtx)

	// Start HTTP server if HTTPAddr is configured
	if cfg.HTTPAddr != "" {
		if err := srv.startHTTPServer(); err != nil {
			cancel()
			_ = h.Close()
			return nil, err
		}
	}

	return srv, nil
}

func (s *AuthServer) Host() host.Host                { return s.host }
func (s *AuthServer) CAPublicKey() *mldsa87.PublicKey { return s.cfg.CAPubKey }
func (s *AuthServer) HTTPAddr() string               { return s.httpAddr }
func (s *AuthServer) AdminToken() string             { return s.cfg.AdminToken }
func (s *AuthServer) Store() *Store                  { return s.store }

// Multiaddr returns the primary full libp2p multiaddr including /p2p/<peer-id>.
func (s *AuthServer) Multiaddr() string {
	addrs := s.host.Addrs()
	if len(addrs) == 0 {
		return ""
	}
	p2pComp, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s", s.host.ID().String()))
	return addrs[0].Encapsulate(p2pComp).String()
}

// Close shuts down the HTTP server, GossipSub topic, and libp2p host.
func (s *AuthServer) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.httpSrv != nil {
		_ = s.httpSrv.Close()
	}
	if s.epochTopic != nil {
		_ = s.epochTopic.Close()
	}
	if s.host != nil {
		return s.host.Close()
	}
	return nil
}

func (s *AuthServer) epochRotationLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.EpochDuration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = s.RotateEpoch(ctx)
		}
	}
}

// RotateEpoch increments the epoch ID, signs the current Poseidon SMT root with the CA key,
// persists the EpochRecord, and broadcasts it over GossipSub (/p2p-auth/epoch/1.0.0).
func (s *AuthServer) RotateEpoch(ctx context.Context) (*authpb.EpochBroadcast, error) {
	s.store.mu.Lock()
	s.store.data.CurrentEpochID++
	epochID := s.store.data.CurrentEpochID
	now := time.Now().Unix()
	validUntil := now + int64(s.cfg.EpochDuration.Seconds())*2
	root := s.smt.Root()
	activeCount := s.smt.ActiveLeafCount()

	eb := &authpb.EpochBroadcast{
		EpochId:           epochID,
		MerkleRoot:        root,
		Timestamp:         now,
		ValidUntil:        validUntil,
		ActiveCredentials: activeCount,
	}
	if err := cred.SignEpochBroadcast(s.cfg.CAPrivKey, s.cfg.CAPubKey, eb); err != nil {
		s.store.mu.Unlock()
		return nil, err
	}

	s.store.data.Epochs[epochID] = &EpochRecord{
		EpochID:           epochID,
		Root:              root,
		Timestamp:         now,
		ValidUntil:        validUntil,
		ActiveCredentials: activeCount,
		CAPubKey:          eb.CaPubkey,
		Signature:         eb.Signature,
	}
	_ = s.store.flushLocked()
	s.store.mu.Unlock()

	if s.epochTopic != nil {
		if payload, err := proto.Marshal(eb); err == nil {
			_ = s.epochTopic.Publish(ctx, payload)
		}
	}

	s.events.Publish(fmt.Sprintf("epoch_rotated: epoch=%d root=%s active=%d", epochID, hex.EncodeToString(root[:8]), activeCount))
	return eb, nil
}

// CurrentEpoch returns the latest signed EpochBroadcast.
func (s *AuthServer) CurrentEpoch() *authpb.EpochBroadcast {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	ep, ok := s.store.data.Epochs[s.store.data.CurrentEpochID]
	if !ok || ep == nil {
		return nil
	}
	return &authpb.EpochBroadcast{
		EpochId:           ep.EpochID,
		MerkleRoot:        ep.Root,
		Timestamp:         ep.Timestamp,
		ValidUntil:        ep.ValidUntil,
		ActiveCredentials: ep.ActiveCredentials,
		CaPubkey:          ep.CAPubKey,
		Signature:         ep.Signature,
	}
}

func (s *AuthServer) handleSyncStream(stream network.Stream) {
	defer stream.Close()
	eb := s.CurrentEpoch()
	if eb == nil {
		return
	}
	_ = wire.WriteMsg(stream, eb)
}

func (s *AuthServer) startHTTPServer() error {
	mux := http.NewServeMux()
	s.registerHTTPRoutes(mux)

	ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listening on HTTP %s: %w", s.cfg.HTTPAddr, err)
	}
	s.httpAddr = ln.Addr().String()
	s.httpSrv = &http.Server{
		Handler: mux,
	}

	go func() {
		if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
			_ = s.httpSrv.ServeTLS(ln, s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			_ = s.httpSrv.Serve(ln)
		}
	}()
	return nil
}
