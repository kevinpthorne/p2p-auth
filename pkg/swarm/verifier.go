package swarm

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/google/uuid"
	"github.com/kevinpthorne/p2p-auth/pkg/circuit"
	"github.com/kevinpthorne/p2p-auth/pkg/cred"
	"github.com/kevinpthorne/p2p-auth/pkg/keystore"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
	"github.com/kevinpthorne/p2p-auth/pkg/wire"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

const (
	ReceiptDomainContext = "p2p-auth:receipt:v1"
	DefaultReceiptTTL    = 15 * time.Minute
	MaxCachedEpochs      = 3 // Current epoch + 2 historical epochs for clock drift/in-flight grace period
)

// Config configures a Decentralized Verification Swarm node (p2p-auth-verifier).
type Config struct {
	HostIdentity   *keystore.IdentityKey
	ListenAddr     string
	BootstrapAddrs []string
	TrustedCAPub   *mldsa87.PublicKey
	VerifyingKey   groth16.VerifyingKey
	ReceiptTTL     time.Duration
}

// VerifierNode is a decentralized libp2p verification swarm peer that subscribes to
// CA-signed EpochBroadcasts, verifies 128-byte Groth16 VerifiablePresentations,
// and issues signed AuthReceipt tickets.
type VerifierNode struct {
	cfg          Config
	host         host.Host
	ps           *pubsub.PubSub
	epochTopic   *pubsub.Topic
	epochSub     *pubsub.Subscription
	receiptTopic *pubsub.Topic

	mu          sync.RWMutex
	latestEpoch uint64
	epochs      map[uint64]*authpb.EpochBroadcast
	receipts    map[string]*authpb.AuthReceipt

	cancel context.CancelFunc
}

// NewVerifierNode initializes and starts a decentralized swarm VerifierNode.
func NewVerifierNode(ctx context.Context, cfg Config) (*VerifierNode, error) {
	if cfg.HostIdentity == nil {
		var err error
		cfg.HostIdentity, err = keystore.GenerateEphemeralIdentity()
		if err != nil {
			return nil, fmt.Errorf("generating verifier identity: %w", err)
		}
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "/ip4/127.0.0.1/tcp/0"
	}
	if cfg.VerifyingKey == nil {
		kb, err := circuit.DefaultKeys()
		if err != nil {
			return nil, fmt.Errorf("loading default Groth16 verifying key: %w", err)
		}
		cfg.VerifyingKey = kb.VK
	}
	if cfg.ReceiptTTL <= 0 {
		cfg.ReceiptTTL = DefaultReceiptTTL
	}

	h, err := libp2p.New(
		libp2p.Identity(cfg.HostIdentity.Libp2pPrivKey()),
		libp2p.ListenAddrStrings(cfg.ListenAddr),
	)
	if err != nil {
		return nil, fmt.Errorf("creating verifier libp2p host: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	ps, err := pubsub.NewGossipSub(runCtx, h)
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, fmt.Errorf("creating verifier GossipSub: %w", err)
	}

	epochTopic, err := ps.Join(wire.TopicEpoch)
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, fmt.Errorf("joining epoch topic: %w", err)
	}
	epochSub, err := epochTopic.Subscribe()
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, fmt.Errorf("subscribing to epoch topic: %w", err)
	}

	receiptTopic, err := ps.Join(wire.TopicReceipts)
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, fmt.Errorf("joining receipt topic: %w", err)
	}
	receiptSub, err := receiptTopic.Subscribe()
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, fmt.Errorf("subscribing to receipt topic: %w", err)
	}

	vn := &VerifierNode{
		cfg:          cfg,
		host:         h,
		ps:           ps,
		epochTopic:   epochTopic,
		epochSub:     epochSub,
		receiptTopic: receiptTopic,
		epochs:       make(map[uint64]*authpb.EpochBroadcast),
		receipts:     make(map[string]*authpb.AuthReceipt),
		cancel:       cancel,
	}

	h.SetStreamHandler(wire.ProtocolSync, vn.handleSyncStream)
	h.SetStreamHandler(wire.ProtocolVerify, vn.HandleVerifyStream)

	go vn.epochLoop(runCtx)
	go vn.receiptLoop(runCtx, receiptSub)

	for _, addrStr := range cfg.BootstrapAddrs {
		_ = vn.ConnectAndSync(runCtx, addrStr)
	}

	return vn, nil
}

func (vn *VerifierNode) Host() host.Host { return vn.host }

func (vn *VerifierNode) Multiaddr() string {
	addrs := vn.host.Addrs()
	if len(addrs) == 0 {
		return ""
	}
	p2pComp, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s", vn.host.ID().String()))
	return addrs[0].Encapsulate(p2pComp).String()
}

func (vn *VerifierNode) Close() error {
	if vn.cancel != nil {
		vn.cancel()
	}
	if vn.epochSub != nil {
		vn.epochSub.Cancel()
	}
	if vn.epochTopic != nil {
		_ = vn.epochTopic.Close()
	}
	if vn.receiptTopic != nil {
		_ = vn.receiptTopic.Close()
	}
	if vn.host != nil {
		return vn.host.Close()
	}
	return nil
}

// ConnectAndSync dials a peer (Central Auth Server or another swarm VerifierNode)
// and synchronizes the latest EpochBroadcast over /p2p-auth/sync/1.0.0.
func (vn *VerifierNode) ConnectAndSync(ctx context.Context, maddrStr string) error {
	ma, err := multiaddr.NewMultiaddr(maddrStr)
	if err != nil {
		return err
	}
	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return err
	}
	if err := vn.host.Connect(ctx, *info); err != nil {
		return err
	}
	stream, err := vn.host.NewStream(ctx, info.ID, wire.ProtocolSync)
	if err != nil {
		return err
	}
	defer stream.Close()

	var eb authpb.EpochBroadcast
	if err := wire.ReadMsg(stream, &eb); err != nil {
		return err
	}
	vn.AdoptEpochBroadcast(&eb)
	return nil
}

// AdoptEpochBroadcast verifies the CA ML-DSA-87 signature on eb and updates the verifier's epoch cache.
// Whenever a new epoch arrives (e.g. upon revocation), older epochs are evicted so revoked credentials
// are rejected immediately across the swarm.
func (vn *VerifierNode) AdoptEpochBroadcast(eb *authpb.EpochBroadcast) bool {
	if !cred.VerifyEpochBroadcast(vn.cfg.TrustedCAPub, eb) {
		return false
	}
	vn.mu.Lock()
	defer vn.mu.Unlock()

	if eb.EpochId < vn.latestEpoch {
		return false
	}
	vn.epochs[eb.EpochId] = eb
	if eb.EpochId > vn.latestEpoch {
		vn.latestEpoch = eb.EpochId
		// Evict superseded epochs so revocations take effect immediately
		for id := range vn.epochs {
			if id < vn.latestEpoch {
				delete(vn.epochs, id)
			}
		}
	}
	return true
}

// LatestEpoch returns the highest verified EpochBroadcast held by this verifier node.
func (vn *VerifierNode) LatestEpoch() *authpb.EpochBroadcast {
	vn.mu.RLock()
	defer vn.mu.RUnlock()
	return vn.epochs[vn.latestEpoch]
}

func (vn *VerifierNode) epochLoop(ctx context.Context) {
	for {
		msg, err := vn.epochSub.Next(ctx)
		if err != nil {
			return
		}
		var eb authpb.EpochBroadcast
		if err := proto.Unmarshal(msg.Data, &eb); err == nil {
			vn.AdoptEpochBroadcast(&eb)
		}
	}
}

func (vn *VerifierNode) receiptLoop(ctx context.Context, sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return
		}
		var receipt authpb.AuthReceipt
		if err := proto.Unmarshal(msg.Data, &receipt); err == nil {
			vn.mu.Lock()
			vn.receipts[receipt.PeerId] = &receipt
			vn.mu.Unlock()
		}
	}
}

func (vn *VerifierNode) handleSyncStream(stream network.Stream) {
	defer stream.Close()
	eb := vn.LatestEpoch()
	if eb == nil {
		return
	}
	_ = wire.WriteMsg(stream, eb)
}

// HandleVerifyStream handles incoming VerifiablePresentations on /p2p-auth/verify/1.0.0.
func (vn *VerifierNode) HandleVerifyStream(stream network.Stream) {
	defer stream.Close()
	var vp authpb.VerifiablePresentation
	if err := wire.ReadMsg(stream, &vp); err != nil {
		return
	}

	receipt, err := vn.VerifyPresentationAndMintReceipt(context.Background(), &vp)
	if err != nil {
		_ = wire.WriteMsg(stream, &authpb.VerifyResponse{
			Valid:        false,
			ErrorMessage: err.Error(),
		})
		return
	}

	_ = wire.WriteMsg(stream, &authpb.VerifyResponse{
		Valid:   true,
		Receipt: receipt,
	})
}

// VerifyPresentationAndMintReceipt validates a VerifiablePresentation against the active EpochRoot
// and signs an AuthReceipt ticket using the verifier's libp2p key.
func (vn *VerifierNode) VerifyPresentationAndMintReceipt(ctx context.Context, vp *authpb.VerifiablePresentation) (*authpb.AuthReceipt, error) {
	vn.mu.RLock()
	eb, ok := vn.epochs[vp.EpochId]
	latest := vn.latestEpoch
	vn.mu.RUnlock()

	if !ok || eb == nil {
		return nil, fmt.Errorf("epoch %d is not active or has been superseded by epoch %d", vp.EpochId, latest)
	}
	if time.Now().Unix() > eb.ValidUntil {
		return nil, fmt.Errorf("epoch %d has expired", vp.EpochId)
	}

	if err := circuit.VerifyPresentation(vn.cfg.VerifyingKey, vp, eb.MerkleRoot); err != nil {
		return nil, err
	}

	uid := uuid.New()
	receipt := &authpb.AuthReceipt{
		ReceiptId:        uid[:],
		Namespace:        vp.Namespace,
		PeerId:           vp.PeerId,
		ClaimsCommitment: vp.ClaimsCommitment,
		EpochId:          vp.EpochId,
		ExpiresAt:        time.Now().Add(vn.cfg.ReceiptTTL).Unix(),
		VerifierPeerId:   vn.host.ID().String(),
	}

	transcript := BuildReceiptTranscript(receipt)
	sig, err := vn.cfg.HostIdentity.Libp2pPrivKey().Sign(transcript)
	if err != nil {
		return nil, fmt.Errorf("signing AuthReceipt: %w", err)
	}
	receipt.VerifierSignature = sig

	if vn.receiptTopic != nil {
		if payload, err := proto.Marshal(receipt); err == nil {
			_ = vn.receiptTopic.Publish(ctx, payload)
		}
	}

	return receipt, nil
}

// BuildReceiptTranscript builds the canonical signing payload for an AuthReceipt.
func BuildReceiptTranscript(r *authpb.AuthReceipt) []byte {
	buf := make([]byte, 0, 160)
	buf = append(buf, []byte(ReceiptDomainContext)...)
	buf = append(buf, r.ReceiptId...)
	buf = append(buf, []byte(r.Namespace)...)
	buf = append(buf, []byte(r.PeerId)...)
	buf = append(buf, r.ClaimsCommitment...)
	var tmp [16]byte
	binary.BigEndian.PutUint64(tmp[0:8], r.EpochId)
	binary.BigEndian.PutUint64(tmp[8:16], uint64(r.ExpiresAt))
	buf = append(buf, tmp[:]...)
	buf = append(buf, []byte(r.VerifierPeerId)...)
	return buf
}
