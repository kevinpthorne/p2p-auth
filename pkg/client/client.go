package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kevinpthorne/p2p-auth/pkg/accumulator"
	"github.com/kevinpthorne/p2p-auth/pkg/adopt"
	"github.com/kevinpthorne/p2p-auth/pkg/circuit"
	"github.com/kevinpthorne/p2p-auth/pkg/cred"
	"github.com/kevinpthorne/p2p-auth/pkg/keystore"
	authpb "github.com/kevinpthorne/p2p-auth/pkg/proto/auth"
	"github.com/kevinpthorne/p2p-auth/pkg/wire"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

type EnrollmentCredential = authpb.VerifiableCredential
type HandshakeProof = authpb.VerifiablePresentation

// Config configures the p2p-auth Appliance Client SDK.
type Config struct {
	Namespace           string
	SubjectID           string
	StateDir            string
	IdentityKey         *keystore.IdentityKey
	IdentityOpts        keystore.Options
	AuthServerMultiaddr string
	VerifierMultiaddr   string
	AdoptionPSK         string
	KeyBundle           *circuit.KeyBundle
}

type AdoptionOptions struct {
	SubjectID         string
	RequestedManifest []byte
	DomainContext     string
}

// Client provides the application-agnostic Holder & Verifier SDK for any libp2p application.
type Client struct {
	cfg        Config
	idKey      *keystore.IdentityKey
	host       host.Host
	kb         *circuit.KeyBundle
	credential *authpb.VerifiableCredential
}

// NewClient initializes the p2p-auth appliance client, loading or generating the node's
// persistent hardware/filesystem identity key.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	idKey := cfg.IdentityKey
	if idKey == nil {
		if cfg.IdentityOpts.KeyFilePath == "" && cfg.StateDir != "" {
			cfg.IdentityOpts.KeyFilePath = filepath.Join(cfg.StateDir, "identity.key")
			cfg.IdentityOpts.AllowCreate = true
		}
		var err error
		idKey, err = keystore.LoadOrInit(cfg.IdentityOpts)
		if err != nil {
			return nil, fmt.Errorf("initializing client identity key: %w", err)
		}
	}

	kb := cfg.KeyBundle
	if kb == nil {
		var err error
		kb, err = circuit.DefaultKeys()
		if err != nil {
			return nil, fmt.Errorf("loading Groth16 keys: %w", err)
		}
	}

	h, err := libp2p.New(
		libp2p.Identity(idKey.Libp2pPrivKey()),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating client libp2p host: %w", err)
	}

	c := &Client{
		cfg:   cfg,
		idKey: idKey,
		host:  h,
		kb:    kb,
	}

	if cfg.StateDir != "" {
		_ = c.loadPersistedCredential()
	}
	return c, nil
}

func (c *Client) PeerID() peer.ID                     { return c.idKey.PeerID() }
func (c *Client) IdentityKey() *keystore.IdentityKey  { return c.idKey }
func (c *Client) Credential() *EnrollmentCredential   { return c.credential }
func (c *Client) SetCredential(vc *EnrollmentCredential) { c.credential = vc }

func (c *Client) Close() error {
	if c.host != nil {
		return c.host.Close()
	}
	return nil
}

func (c *Client) loadPersistedCredential() error {
	credPath := filepath.Join(c.cfg.StateDir, "credential.zkp")
	data, err := os.ReadFile(credPath)
	if err != nil {
		return err
	}
	var vc authpb.VerifiableCredential
	if err := proto.Unmarshal(data, &vc); err != nil {
		return err
	}
	if vc.Namespace == c.cfg.Namespace && vc.Subject == "did:p2p:"+c.idKey.PeerID().String() {
		c.credential = &vc
	}
	return nil
}

func (c *Client) persistCredential(vc *authpb.VerifiableCredential) error {
	if c.cfg.StateDir == "" {
		return nil
	}
	if err := os.MkdirAll(c.cfg.StateDir, 0700); err != nil {
		return err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(vc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.cfg.StateDir, "credential.zkp"), raw, 0600); err != nil {
		return err
	}
	if len(vc.ManifestPayload) > 0 {
		_ = os.WriteFile(filepath.Join(c.cfg.StateDir, "manifest.bin"), vc.ManifestPayload, 0600)
	}
	if len(vc.ManifestCaSignature) > 0 {
		_ = os.WriteFile(filepath.Join(c.cfg.StateDir, "manifest.sig"), vc.ManifestCaSignature, 0600)
	}
	return nil
}

// EnsureEnrolled checks for an existing valid VerifiableCredential on disk and, if missing,
// executes single-pass PSK adoption using the configured AdoptionPSK.
func (c *Client) EnsureEnrolled(ctx context.Context) (*EnrollmentCredential, error) {
	if c.credential != nil {
		return c.credential, nil
	}
	if err := c.loadPersistedCredential(); err == nil && c.credential != nil {
		return c.credential, nil
	}
	psk := c.cfg.AdoptionPSK
	if psk == "" {
		psk = os.Getenv("P2P_AUTH_ADOPTION_PSK")
	}
	if psk == "" {
		return nil, errors.New("no persisted credential found and no AdoptionPSK configured")
	}
	return c.AdoptWithPSK(ctx, psk, AdoptionOptions{
		SubjectID: c.cfg.SubjectID,
	})
}

// AdoptWithPSK performs first-boot PSK adoption over /p2p-auth/adopt/1.0.0.
// If the PSK is in QUEUE mode (ADOPTION_PENDING), it waits on the open stream until approved.
func (c *Client) AdoptWithPSK(ctx context.Context, pskToken string, opts AdoptionOptions) (*EnrollmentCredential, error) {
	info, err := parseMultiaddr(c.cfg.AuthServerMultiaddr)
	if err != nil {
		return nil, fmt.Errorf("parsing AuthServerMultiaddr: %w", err)
	}
	if err := c.host.Connect(ctx, *info); err != nil {
		return nil, fmt.Errorf("connecting to Auth Server: %w", err)
	}

	stream, err := c.host.NewStream(ctx, info.ID, wire.ProtocolAdopt)
	if err != nil {
		return nil, fmt.Errorf("opening adopt stream: %w", err)
	}
	defer stream.Close()

	subj := opts.SubjectID
	if subj == "" {
		subj = c.cfg.SubjectID
	}

	req := &authpb.AdoptionRequest{
		Namespace:         c.cfg.Namespace,
		SubjectId:         subj,
		RequestedManifest: opts.RequestedManifest,
		DomainContext:     opts.DomainContext,
	}
	if err := adopt.SignAdoptionRequest(req, c.idKey, pskToken); err != nil {
		return nil, err
	}

	if err := wire.WriteMsg(stream, req); err != nil {
		return nil, fmt.Errorf("sending AdoptionRequest: %w", err)
	}

	for {
		var resp authpb.AdoptionResponse
		if err := wire.ReadMsg(stream, &resp); err != nil {
			return nil, fmt.Errorf("reading AdoptionResponse: %w", err)
		}
		switch resp.State {
		case authpb.AdoptionState_ADOPTION_APPROVED:
			if resp.Credential == nil {
				return nil, errors.New("server returned ADOPTION_APPROVED without credential")
			}
			c.credential = resp.Credential
			_ = c.persistCredential(resp.Credential)
			return resp.Credential, nil
		case authpb.AdoptionState_ADOPTION_REJECTED:
			return nil, fmt.Errorf("adoption rejected: %s", resp.StatusMessage)
		case authpb.AdoptionState_ADOPTION_PENDING:
			// Continue reading from open stream until operator approves
			continue
		}
	}
}

// Enroll enrolls a node that already holds a CA-signed opaque payload over /p2p-auth/enroll/1.0.0.
func (c *Client) Enroll(ctx context.Context, payload []byte, caSig []byte, domainContext string) (*EnrollmentCredential, error) {
	info, err := parseMultiaddr(c.cfg.AuthServerMultiaddr)
	if err != nil {
		return nil, fmt.Errorf("parsing AuthServerMultiaddr: %w", err)
	}
	if err := c.host.Connect(ctx, *info); err != nil {
		return nil, fmt.Errorf("connecting to Auth Server: %w", err)
	}

	stream, err := c.host.NewStream(ctx, info.ID, wire.ProtocolEnroll)
	if err != nil {
		return nil, fmt.Errorf("opening enroll stream: %w", err)
	}
	defer stream.Close()

	req := &authpb.EnrollmentRequest{
		Namespace:       c.cfg.Namespace,
		PeerId:          c.idKey.PeerID().String(),
		DomainContext:   cred.ResolveDomainContext(domainContext),
		ManifestPayload: payload,
		CaSignature:     caSig,
		Timestamp:       time.Now().Unix(),
	}
	transcript := adopt.BuildEnrollmentTranscript(req)
	popSig, err := c.idKey.Libp2pPrivKey().Sign(transcript)
	if err != nil {
		return nil, err
	}
	req.PopSignature = popSig

	if err := wire.WriteMsg(stream, req); err != nil {
		return nil, err
	}
	var vc authpb.VerifiableCredential
	if err := wire.ReadMsg(stream, &vc); err != nil {
		return nil, err
	}
	c.credential = &vc
	_ = c.persistCredential(&vc)
	return &vc, nil
}

// GenerateHandshakeProof generates a 128-byte Groth16 VerifiablePresentation for the given challenge.
func (c *Client) GenerateHandshakeProof(ctx context.Context, challenge []byte, discloseClaims bool) (*HandshakeProof, error) {
	if c.credential == nil {
		return nil, errors.New("no VerifiableCredential loaded on client")
	}
	return c.kb.ProvePresentation(c.credential, c.idKey.PeerID().String(), challenge, time.Now().Unix(), discloseClaims)
}

// VerifyPeerProof verifies a remote peer's VerifiablePresentation locally against the known EpochRoot
// and optional expected opaque manifest bytes.
func (c *Client) VerifyPeerProof(ctx context.Context, proof *HandshakeProof, remotePeer peer.ID, expectedManifest []byte, trustedEpochRoot []byte) (bool, error) {
	if proof == nil {
		return false, errors.New("proof is nil")
	}
	if remotePeer != "" && proof.PeerId != remotePeer.String() {
		return false, errors.New("proof PeerId does not match remotePeer")
	}
	if len(expectedManifest) > 0 {
		expectedCommit := accumulator.PoseidonBytes(expectedManifest)
		if !bytes.Equal(proof.ClaimsCommitment, expectedCommit) {
			return false, errors.New("proof ClaimsCommitment does not match expected manifest")
		}
	}
	if err := circuit.VerifyPresentation(c.kb.VK, proof, trustedEpochRoot); err != nil {
		return false, err
	}
	return true, nil
}

// RequestSwarmTicket sends a VerifiablePresentation to a decentralized Verification Swarm node
// over /p2p-auth/verify/1.0.0 and returns the signed AuthReceipt.
func (c *Client) RequestSwarmTicket(ctx context.Context, proof *HandshakeProof) (*authpb.AuthReceipt, error) {
	info, err := parseMultiaddr(c.cfg.VerifierMultiaddr)
	if err != nil {
		return nil, fmt.Errorf("parsing VerifierMultiaddr: %w", err)
	}
	if err := c.host.Connect(ctx, *info); err != nil {
		return nil, fmt.Errorf("connecting to Verifier Swarm node: %w", err)
	}
	stream, err := c.host.NewStream(ctx, info.ID, wire.ProtocolVerify)
	if err != nil {
		return nil, fmt.Errorf("opening verify stream: %w", err)
	}
	defer stream.Close()

	if err := wire.WriteMsg(stream, proof); err != nil {
		return nil, fmt.Errorf("writing VerifiablePresentation: %w", err)
	}
	var resp authpb.VerifyResponse
	if err := wire.ReadMsg(stream, &resp); err != nil {
		return nil, fmt.Errorf("reading VerifyResponse: %w", err)
	}
	if !resp.Valid || resp.Receipt == nil {
		return nil, fmt.Errorf("swarm verification rejected proof: %s", resp.ErrorMessage)
	}
	return resp.Receipt, nil
}

func parseMultiaddr(s string) (*peer.AddrInfo, error) {
	if s == "" {
		return nil, errors.New("empty multiaddr")
	}
	ma, err := multiaddr.NewMultiaddr(s)
	if err != nil {
		return nil, err
	}
	return peer.AddrInfoFromP2pAddr(ma)
}
