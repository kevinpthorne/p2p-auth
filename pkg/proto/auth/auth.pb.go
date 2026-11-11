// Code generated for proto/auth.proto. DO NOT EDIT.
// source: auth.proto

package auth

import (
	reflect "reflect"
	sync "sync"

	proto "google.golang.org/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AdoptionState int32

const (
	AdoptionState_ADOPTION_PENDING  AdoptionState = 0
	AdoptionState_ADOPTION_APPROVED AdoptionState = 1
	AdoptionState_ADOPTION_REJECTED AdoptionState = 2
)

var (
	AdoptionState_name = map[int32]string{
		0: "ADOPTION_PENDING",
		1: "ADOPTION_APPROVED",
		2: "ADOPTION_REJECTED",
	}
	AdoptionState_value = map[string]int32{
		"ADOPTION_PENDING":  0,
		"ADOPTION_APPROVED": 1,
		"ADOPTION_REJECTED": 2,
	}
)

func (x AdoptionState) Enum() *AdoptionState {
	p := new(AdoptionState)
	*p = x
	return p
}

func (x AdoptionState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AdoptionState) Descriptor() protoreflect.EnumDescriptor {
	return file_auth_proto_enumTypes[0].Descriptor()
}

func (AdoptionState) Type() protoreflect.EnumType {
	return &file_auth_proto_enumTypes[0]
}

func (x AdoptionState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// AdoptionRequest is sent by a first-boot node using a Pre-Shared Key (PSK)
// without any pre-existing signed manifest files.
type AdoptionRequest struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	Namespace         string                 `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	PeerId            string                 `protobuf:"bytes,2,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	PubKey            []byte                 `protobuf:"bytes,3,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
	KeystoreTier      string                 `protobuf:"bytes,4,opt,name=keystore_tier,json=keystoreTier,proto3" json:"keystore_tier,omitempty"`
	SubjectId         string                 `protobuf:"bytes,5,opt,name=subject_id,json=subjectId,proto3" json:"subject_id,omitempty"`
	RequestedManifest []byte                 `protobuf:"bytes,6,opt,name=requested_manifest,json=requestedManifest,proto3" json:"requested_manifest,omitempty"`
	DomainContext     string                 `protobuf:"bytes,7,opt,name=domain_context,json=domainContext,proto3" json:"domain_context,omitempty"`
	Timestamp         int64                  `protobuf:"varint,8,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Nonce             []byte                 `protobuf:"bytes,9,opt,name=nonce,proto3" json:"nonce,omitempty"`
	PopSignature      []byte                 `protobuf:"bytes,10,opt,name=pop_signature,json=popSignature,proto3" json:"pop_signature,omitempty"`
	PskId             string                 `protobuf:"bytes,11,opt,name=psk_id,json=pskId,proto3" json:"psk_id,omitempty"`
	PskHmac           []byte                 `protobuf:"bytes,12,opt,name=psk_hmac,json=pskHmac,proto3" json:"psk_hmac,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *AdoptionRequest) Reset() {
	*x = AdoptionRequest{}
	mi := &file_auth_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdoptionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdoptionRequest) ProtoMessage() {}

func (x *AdoptionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *AdoptionRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}
func (x *AdoptionRequest) GetPeerId() string {
	if x != nil {
		return x.PeerId
	}
	return ""
}
func (x *AdoptionRequest) GetPubKey() []byte {
	if x != nil {
		return x.PubKey
	}
	return nil
}
func (x *AdoptionRequest) GetKeystoreTier() string {
	if x != nil {
		return x.KeystoreTier
	}
	return ""
}
func (x *AdoptionRequest) GetSubjectId() string {
	if x != nil {
		return x.SubjectId
	}
	return ""
}
func (x *AdoptionRequest) GetRequestedManifest() []byte {
	if x != nil {
		return x.RequestedManifest
	}
	return nil
}
func (x *AdoptionRequest) GetDomainContext() string {
	if x != nil {
		return x.DomainContext
	}
	return ""
}
func (x *AdoptionRequest) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}
func (x *AdoptionRequest) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}
func (x *AdoptionRequest) GetPopSignature() []byte {
	if x != nil {
		return x.PopSignature
	}
	return nil
}
func (x *AdoptionRequest) GetPskId() string {
	if x != nil {
		return x.PskId
	}
	return ""
}
func (x *AdoptionRequest) GetPskHmac() []byte {
	if x != nil {
		return x.PskHmac
	}
	return nil
}

type AdoptionResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	State         AdoptionState          `protobuf:"varint,1,opt,name=state,proto3,enum=p2pauth.v1.AdoptionState" json:"state,omitempty"`
	StatusMessage string                 `protobuf:"bytes,2,opt,name=status_message,json=statusMessage,proto3" json:"status_message,omitempty"`
	Credential    *VerifiableCredential  `protobuf:"bytes,3,opt,name=credential,proto3" json:"credential,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AdoptionResponse) Reset() {
	*x = AdoptionResponse{}
	mi := &file_auth_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdoptionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdoptionResponse) ProtoMessage() {}

func (x *AdoptionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *AdoptionResponse) GetState() AdoptionState {
	if x != nil {
		return x.State
	}
	return AdoptionState_ADOPTION_PENDING
}
func (x *AdoptionResponse) GetStatusMessage() string {
	if x != nil {
		return x.StatusMessage
	}
	return ""
}
func (x *AdoptionResponse) GetCredential() *VerifiableCredential {
	if x != nil {
		return x.Credential
	}
	return nil
}

// EnrollmentRequest is sent by nodes already holding a CA-signed opaque payload.
type EnrollmentRequest struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	Namespace       string                 `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	PeerId          string                 `protobuf:"bytes,2,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	DomainContext   string                 `protobuf:"bytes,3,opt,name=domain_context,json=domainContext,proto3" json:"domain_context,omitempty"`
	ManifestPayload []byte                 `protobuf:"bytes,4,opt,name=manifest_payload,json=manifestPayload,proto3" json:"manifest_payload,omitempty"`
	CaSignature     []byte                 `protobuf:"bytes,5,opt,name=ca_signature,json=caSignature,proto3" json:"ca_signature,omitempty"`
	Timestamp       int64                  `protobuf:"varint,6,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	PopSignature    []byte                 `protobuf:"bytes,7,opt,name=pop_signature,json=popSignature,proto3" json:"pop_signature,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *EnrollmentRequest) Reset() {
	*x = EnrollmentRequest{}
	mi := &file_auth_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EnrollmentRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnrollmentRequest) ProtoMessage() {}

func (x *EnrollmentRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *EnrollmentRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}
func (x *EnrollmentRequest) GetPeerId() string {
	if x != nil {
		return x.PeerId
	}
	return ""
}
func (x *EnrollmentRequest) GetDomainContext() string {
	if x != nil {
		return x.DomainContext
	}
	return ""
}
func (x *EnrollmentRequest) GetManifestPayload() []byte {
	if x != nil {
		return x.ManifestPayload
	}
	return nil
}
func (x *EnrollmentRequest) GetCaSignature() []byte {
	if x != nil {
		return x.CaSignature
	}
	return nil
}
func (x *EnrollmentRequest) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}
func (x *EnrollmentRequest) GetPopSignature() []byte {
	if x != nil {
		return x.PopSignature
	}
	return nil
}

// VerifiableCredential is issued by p2p-auth-server and persisted by the Holder as credential.zkp.
type VerifiableCredential struct {
	state               protoimpl.MessageState `protogen:"open.v1"`
	Id                  string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Issuer              string                 `protobuf:"bytes,2,opt,name=issuer,proto3" json:"issuer,omitempty"`
	Subject             string                 `protobuf:"bytes,3,opt,name=subject,proto3" json:"subject,omitempty"`
	Namespace           string                 `protobuf:"bytes,4,opt,name=namespace,proto3" json:"namespace,omitempty"`
	SerialNumber        uint64                 `protobuf:"varint,5,opt,name=serial_number,json=serialNumber,proto3" json:"serial_number,omitempty"`
	NotBefore           int64                  `protobuf:"varint,6,opt,name=not_before,json=notBefore,proto3" json:"not_before,omitempty"`
	NotAfter            int64                  `protobuf:"varint,7,opt,name=not_after,json=notAfter,proto3" json:"not_after,omitempty"`
	ManifestPayload     []byte                 `protobuf:"bytes,8,opt,name=manifest_payload,json=manifestPayload,proto3" json:"manifest_payload,omitempty"`
	ClaimsCommitment    []byte                 `protobuf:"bytes,9,opt,name=claims_commitment,json=claimsCommitment,proto3" json:"claims_commitment,omitempty"`
	CredentialSecret    []byte                 `protobuf:"bytes,10,opt,name=credential_secret,json=credentialSecret,proto3" json:"credential_secret,omitempty"`
	EpochId             uint64                 `protobuf:"varint,11,opt,name=epoch_id,json=epochId,proto3" json:"epoch_id,omitempty"`
	EpochRoot           []byte                 `protobuf:"bytes,12,opt,name=epoch_root,json=epochRoot,proto3" json:"epoch_root,omitempty"`
	LeafIndex           uint32                 `protobuf:"varint,13,opt,name=leaf_index,json=leafIndex,proto3" json:"leaf_index,omitempty"`
	MerkleSiblings      [][]byte               `protobuf:"bytes,14,rep,name=merkle_siblings,json=merkleSiblings,proto3" json:"merkle_siblings,omitempty"`
	PathDirections      uint32                 `protobuf:"varint,15,opt,name=path_directions,json=pathDirections,proto3" json:"path_directions,omitempty"`
	ManifestCaSignature []byte                 `protobuf:"bytes,16,opt,name=manifest_ca_signature,json=manifestCaSignature,proto3" json:"manifest_ca_signature,omitempty"`
	EpochSignature      []byte                 `protobuf:"bytes,17,opt,name=epoch_signature,json=epochSignature,proto3" json:"epoch_signature,omitempty"`
	DomainContext       string                 `protobuf:"bytes,18,opt,name=domain_context,json=domainContext,proto3" json:"domain_context,omitempty"`
	unknownFields       protoimpl.UnknownFields
	sizeCache           protoimpl.SizeCache
}

// EnrollmentResponse is a type alias for VerifiableCredential.
type EnrollmentResponse = VerifiableCredential

func (x *VerifiableCredential) Reset() {
	*x = VerifiableCredential{}
	mi := &file_auth_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VerifiableCredential) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifiableCredential) ProtoMessage() {}

func (x *VerifiableCredential) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *VerifiableCredential) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}
func (x *VerifiableCredential) GetIssuer() string {
	if x != nil {
		return x.Issuer
	}
	return ""
}
func (x *VerifiableCredential) GetSubject() string {
	if x != nil {
		return x.Subject
	}
	return ""
}
func (x *VerifiableCredential) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}
func (x *VerifiableCredential) GetSerialNumber() uint64 {
	if x != nil {
		return x.SerialNumber
	}
	return 0
}
func (x *VerifiableCredential) GetNotBefore() int64 {
	if x != nil {
		return x.NotBefore
	}
	return 0
}
func (x *VerifiableCredential) GetNotAfter() int64 {
	if x != nil {
		return x.NotAfter
	}
	return 0
}
func (x *VerifiableCredential) GetManifestPayload() []byte {
	if x != nil {
		return x.ManifestPayload
	}
	return nil
}
func (x *VerifiableCredential) GetClaimsCommitment() []byte {
	if x != nil {
		return x.ClaimsCommitment
	}
	return nil
}
func (x *VerifiableCredential) GetCredentialSecret() []byte {
	if x != nil {
		return x.CredentialSecret
	}
	return nil
}
func (x *VerifiableCredential) GetEpochId() uint64 {
	if x != nil {
		return x.EpochId
	}
	return 0
}
func (x *VerifiableCredential) GetEpochRoot() []byte {
	if x != nil {
		return x.EpochRoot
	}
	return nil
}
func (x *VerifiableCredential) GetLeafIndex() uint32 {
	if x != nil {
		return x.LeafIndex
	}
	return 0
}
func (x *VerifiableCredential) GetMerkleSiblings() [][]byte {
	if x != nil {
		return x.MerkleSiblings
	}
	return nil
}
func (x *VerifiableCredential) GetPathDirections() uint32 {
	if x != nil {
		return x.PathDirections
	}
	return 0
}
func (x *VerifiableCredential) GetManifestCaSignature() []byte {
	if x != nil {
		return x.ManifestCaSignature
	}
	return nil
}
func (x *VerifiableCredential) GetEpochSignature() []byte {
	if x != nil {
		return x.EpochSignature
	}
	return nil
}
func (x *VerifiableCredential) GetDomainContext() string {
	if x != nil {
		return x.DomainContext
	}
	return ""
}

type EpochBroadcast struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	EpochId           uint64                 `protobuf:"varint,1,opt,name=epoch_id,json=epochId,proto3" json:"epoch_id,omitempty"`
	MerkleRoot        []byte                 `protobuf:"bytes,2,opt,name=merkle_root,json=merkleRoot,proto3" json:"merkle_root,omitempty"`
	Timestamp         int64                  `protobuf:"varint,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	ValidUntil        int64                  `protobuf:"varint,4,opt,name=valid_until,json=validUntil,proto3" json:"valid_until,omitempty"`
	ActiveCredentials uint32                 `protobuf:"varint,5,opt,name=active_credentials,json=activeCredentials,proto3" json:"active_credentials,omitempty"`
	CaPubkey          []byte                 `protobuf:"bytes,6,opt,name=ca_pubkey,json=caPubkey,proto3" json:"ca_pubkey,omitempty"`
	Signature         []byte                 `protobuf:"bytes,7,opt,name=signature,proto3" json:"signature,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *EpochBroadcast) Reset() {
	*x = EpochBroadcast{}
	mi := &file_auth_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EpochBroadcast) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EpochBroadcast) ProtoMessage() {}

func (x *EpochBroadcast) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *EpochBroadcast) GetEpochId() uint64 {
	if x != nil {
		return x.EpochId
	}
	return 0
}
func (x *EpochBroadcast) GetMerkleRoot() []byte {
	if x != nil {
		return x.MerkleRoot
	}
	return nil
}
func (x *EpochBroadcast) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}
func (x *EpochBroadcast) GetValidUntil() int64 {
	if x != nil {
		return x.ValidUntil
	}
	return 0
}
func (x *EpochBroadcast) GetActiveCredentials() uint32 {
	if x != nil {
		return x.ActiveCredentials
	}
	return 0
}
func (x *EpochBroadcast) GetCaPubkey() []byte {
	if x != nil {
		return x.CaPubkey
	}
	return nil
}
func (x *EpochBroadcast) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

// VerifiablePresentation is presented during peer-to-peer or verification swarm handshakes.
type VerifiablePresentation struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	EpochId          uint64                 `protobuf:"varint,1,opt,name=epoch_id,json=epochId,proto3" json:"epoch_id,omitempty"`
	Namespace        string                 `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	PeerId           string                 `protobuf:"bytes,3,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	ClaimsCommitment []byte                 `protobuf:"bytes,4,opt,name=claims_commitment,json=claimsCommitment,proto3" json:"claims_commitment,omitempty"`
	SessionChallenge []byte                 `protobuf:"bytes,5,opt,name=session_challenge,json=sessionChallenge,proto3" json:"session_challenge,omitempty"`
	ChallengeTag     []byte                 `protobuf:"bytes,6,opt,name=challenge_tag,json=challengeTag,proto3" json:"challenge_tag,omitempty"`
	Timestamp        int64                  `protobuf:"varint,7,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Groth16Proof     []byte                 `protobuf:"bytes,8,opt,name=groth16_proof,json=groth16Proof,proto3" json:"groth16_proof,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

// VerifyRequest is a type alias for VerifiablePresentation.
type VerifyRequest = VerifiablePresentation

func (x *VerifiablePresentation) Reset() {
	*x = VerifiablePresentation{}
	mi := &file_auth_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VerifiablePresentation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifiablePresentation) ProtoMessage() {}

func (x *VerifiablePresentation) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *VerifiablePresentation) GetEpochId() uint64 {
	if x != nil {
		return x.EpochId
	}
	return 0
}
func (x *VerifiablePresentation) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}
func (x *VerifiablePresentation) GetPeerId() string {
	if x != nil {
		return x.PeerId
	}
	return ""
}
func (x *VerifiablePresentation) GetClaimsCommitment() []byte {
	if x != nil {
		return x.ClaimsCommitment
	}
	return nil
}
func (x *VerifiablePresentation) GetSessionChallenge() []byte {
	if x != nil {
		return x.SessionChallenge
	}
	return nil
}
func (x *VerifiablePresentation) GetChallengeTag() []byte {
	if x != nil {
		return x.ChallengeTag
	}
	return nil
}
func (x *VerifiablePresentation) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}
func (x *VerifiablePresentation) GetGroth16Proof() []byte {
	if x != nil {
		return x.Groth16Proof
	}
	return nil
}

type AuthReceipt struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	ReceiptId         []byte                 `protobuf:"bytes,1,opt,name=receipt_id,json=receiptId,proto3" json:"receipt_id,omitempty"`
	Namespace         string                 `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	PeerId            string                 `protobuf:"bytes,3,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	ClaimsCommitment  []byte                 `protobuf:"bytes,4,opt,name=claims_commitment,json=claimsCommitment,proto3" json:"claims_commitment,omitempty"`
	EpochId           uint64                 `protobuf:"varint,5,opt,name=epoch_id,json=epochId,proto3" json:"epoch_id,omitempty"`
	ExpiresAt         int64                  `protobuf:"varint,6,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	VerifierPeerId    string                 `protobuf:"bytes,7,opt,name=verifier_peer_id,json=verifierPeerId,proto3" json:"verifier_peer_id,omitempty"`
	VerifierSignature []byte                 `protobuf:"bytes,8,opt,name=verifier_signature,json=verifierSignature,proto3" json:"verifier_signature,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *AuthReceipt) Reset() {
	*x = AuthReceipt{}
	mi := &file_auth_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AuthReceipt) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthReceipt) ProtoMessage() {}

func (x *AuthReceipt) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *AuthReceipt) GetReceiptId() []byte {
	if x != nil {
		return x.ReceiptId
	}
	return nil
}
func (x *AuthReceipt) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}
func (x *AuthReceipt) GetPeerId() string {
	if x != nil {
		return x.PeerId
	}
	return ""
}
func (x *AuthReceipt) GetClaimsCommitment() []byte {
	if x != nil {
		return x.ClaimsCommitment
	}
	return nil
}
func (x *AuthReceipt) GetEpochId() uint64 {
	if x != nil {
		return x.EpochId
	}
	return 0
}
func (x *AuthReceipt) GetExpiresAt() int64 {
	if x != nil {
		return x.ExpiresAt
	}
	return 0
}
func (x *AuthReceipt) GetVerifierPeerId() string {
	if x != nil {
		return x.VerifierPeerId
	}
	return ""
}
func (x *AuthReceipt) GetVerifierSignature() []byte {
	if x != nil {
		return x.VerifierSignature
	}
	return nil
}

type VerifyResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Valid         bool                   `protobuf:"varint,1,opt,name=valid,proto3" json:"valid,omitempty"`
	ErrorMessage  string                 `protobuf:"bytes,2,opt,name=error_message,json=errorMessage,proto3" json:"error_message,omitempty"`
	Receipt       *AuthReceipt           `protobuf:"bytes,3,opt,name=receipt,proto3" json:"receipt,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *VerifyResponse) Reset() {
	*x = VerifyResponse{}
	mi := &file_auth_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VerifyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyResponse) ProtoMessage() {}

func (x *VerifyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *VerifyResponse) GetValid() bool {
	if x != nil {
		return x.Valid
	}
	return false
}
func (x *VerifyResponse) GetErrorMessage() string {
	if x != nil {
		return x.ErrorMessage
	}
	return ""
}
func (x *VerifyResponse) GetReceipt() *AuthReceipt {
	if x != nil {
		return x.Receipt
	}
	return nil
}

var File_auth_proto protoreflect.FileDescriptor

var file_auth_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_auth_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_auth_proto_goTypes = []any{
	(AdoptionState)(0),              // 0: p2pauth.v1.AdoptionState
	(*AdoptionRequest)(nil),         // 1: p2pauth.v1.AdoptionRequest
	(*AdoptionResponse)(nil),        // 2: p2pauth.v1.AdoptionResponse
	(*EnrollmentRequest)(nil),       // 3: p2pauth.v1.EnrollmentRequest
	(*VerifiableCredential)(nil),    // 4: p2pauth.v1.VerifiableCredential
	(*EpochBroadcast)(nil),          // 5: p2pauth.v1.EpochBroadcast
	(*VerifiablePresentation)(nil),  // 6: p2pauth.v1.VerifiablePresentation
	(*AuthReceipt)(nil),             // 7: p2pauth.v1.AuthReceipt
	(*VerifyResponse)(nil),          // 8: p2pauth.v1.VerifyResponse
}
var file_auth_proto_depIdxs = []int32{
	0, // 0: p2pauth.v1.AdoptionResponse.state:type_name -> p2pauth.v1.AdoptionState
	4, // 1: p2pauth.v1.AdoptionResponse.credential:type_name -> p2pauth.v1.VerifiableCredential
	7, // 2: p2pauth.v1.VerifyResponse.receipt:type_name -> p2pauth.v1.AuthReceipt
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

var file_auth_proto_initOnce sync.Once

func fProto(name string, num int32, label descriptorpb.FieldDescriptorProto_Label, typ descriptorpb.FieldDescriptorProto_Type, typeName string, jsonName string) *descriptorpb.FieldDescriptorProto {
	f := &descriptorpb.FieldDescriptorProto{
		Name:     proto.String(name),
		Number:   proto.Int32(num),
		Label:    label.Enum(),
		Type:     typ.Enum(),
		JsonName: proto.String(jsonName),
	}
	if typeName != "" {
		f.TypeName = proto.String(typeName)
	}
	return f
}

func init() { file_auth_proto_init() }

func file_auth_proto_init() {
	file_auth_proto_initOnce.Do(func() {
		opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
		rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
		tStr := descriptorpb.FieldDescriptorProto_TYPE_STRING
		tBytes := descriptorpb.FieldDescriptorProto_TYPE_BYTES
		tInt64 := descriptorpb.FieldDescriptorProto_TYPE_INT64
		tUint64 := descriptorpb.FieldDescriptorProto_TYPE_UINT64
		tUint32 := descriptorpb.FieldDescriptorProto_TYPE_UINT32
		tBool := descriptorpb.FieldDescriptorProto_TYPE_BOOL
		tEnum := descriptorpb.FieldDescriptorProto_TYPE_ENUM
		tMsg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE

		fdp := &descriptorpb.FileDescriptorProto{
			Syntax:  proto.String("proto3"),
			Name:    proto.String("auth.proto"),
			Package: proto.String("p2pauth.v1"),
			Options: &descriptorpb.FileOptions{
				GoPackage: proto.String("github.com/kevinpthorne/p2p-auth/pkg/proto/auth;auth"),
			},
			EnumType: []*descriptorpb.EnumDescriptorProto{
				{
					Name: proto.String("AdoptionState"),
					Value: []*descriptorpb.EnumValueDescriptorProto{
						{Name: proto.String("ADOPTION_PENDING"), Number: proto.Int32(0)},
						{Name: proto.String("ADOPTION_APPROVED"), Number: proto.Int32(1)},
						{Name: proto.String("ADOPTION_REJECTED"), Number: proto.Int32(2)},
					},
				},
			},
			MessageType: []*descriptorpb.DescriptorProto{
				{
					Name: proto.String("AdoptionRequest"),
					Field: []*descriptorpb.FieldDescriptorProto{
						fProto("namespace", 1, opt, tStr, "", "namespace"),
						fProto("peer_id", 2, opt, tStr, "", "peerId"),
						fProto("pub_key", 3, opt, tBytes, "", "pubKey"),
						fProto("keystore_tier", 4, opt, tStr, "", "keystoreTier"),
						fProto("subject_id", 5, opt, tStr, "", "subjectId"),
						fProto("requested_manifest", 6, opt, tBytes, "", "requestedManifest"),
						fProto("domain_context", 7, opt, tStr, "", "domainContext"),
						fProto("timestamp", 8, opt, tInt64, "", "timestamp"),
						fProto("nonce", 9, opt, tBytes, "", "nonce"),
						fProto("pop_signature", 10, opt, tBytes, "", "popSignature"),
						fProto("psk_id", 11, opt, tStr, "", "pskId"),
						fProto("psk_hmac", 12, opt, tBytes, "", "pskHmac"),
					},
				},
				{
					Name: proto.String("AdoptionResponse"),
					Field: []*descriptorpb.FieldDescriptorProto{
						fProto("state", 1, opt, tEnum, ".p2pauth.v1.AdoptionState", "state"),
						fProto("status_message", 2, opt, tStr, "", "statusMessage"),
						fProto("credential", 3, opt, tMsg, ".p2pauth.v1.VerifiableCredential", "credential"),
					},
				},
				{
					Name: proto.String("EnrollmentRequest"),
					Field: []*descriptorpb.FieldDescriptorProto{
						fProto("namespace", 1, opt, tStr, "", "namespace"),
						fProto("peer_id", 2, opt, tStr, "", "peerId"),
						fProto("domain_context", 3, opt, tStr, "", "domainContext"),
						fProto("manifest_payload", 4, opt, tBytes, "", "manifestPayload"),
						fProto("ca_signature", 5, opt, tBytes, "", "caSignature"),
						fProto("timestamp", 6, opt, tInt64, "", "timestamp"),
						fProto("pop_signature", 7, opt, tBytes, "", "popSignature"),
					},
				},
				{
					Name: proto.String("VerifiableCredential"),
					Field: []*descriptorpb.FieldDescriptorProto{
						fProto("id", 1, opt, tStr, "", "id"),
						fProto("issuer", 2, opt, tStr, "", "issuer"),
						fProto("subject", 3, opt, tStr, "", "subject"),
						fProto("namespace", 4, opt, tStr, "", "namespace"),
						fProto("serial_number", 5, opt, tUint64, "", "serialNumber"),
						fProto("not_before", 6, opt, tInt64, "", "notBefore"),
						fProto("not_after", 7, opt, tInt64, "", "notAfter"),
						fProto("manifest_payload", 8, opt, tBytes, "", "manifestPayload"),
						fProto("claims_commitment", 9, opt, tBytes, "", "claimsCommitment"),
						fProto("credential_secret", 10, opt, tBytes, "", "credentialSecret"),
						fProto("epoch_id", 11, opt, tUint64, "", "epochId"),
						fProto("epoch_root", 12, opt, tBytes, "", "epochRoot"),
						fProto("leaf_index", 13, opt, tUint32, "", "leafIndex"),
						fProto("merkle_siblings", 14, rep, tBytes, "", "merkleSiblings"),
						fProto("path_directions", 15, opt, tUint32, "", "pathDirections"),
						fProto("manifest_ca_signature", 16, opt, tBytes, "", "manifestCaSignature"),
						fProto("epoch_signature", 17, opt, tBytes, "", "epochSignature"),
						fProto("domain_context", 18, opt, tStr, "", "domainContext"),
					},
				},
				{
					Name: proto.String("EpochBroadcast"),
					Field: []*descriptorpb.FieldDescriptorProto{
						fProto("epoch_id", 1, opt, tUint64, "", "epochId"),
						fProto("merkle_root", 2, opt, tBytes, "", "merkleRoot"),
						fProto("timestamp", 3, opt, tInt64, "", "timestamp"),
						fProto("valid_until", 4, opt, tInt64, "", "validUntil"),
						fProto("active_credentials", 5, opt, tUint32, "", "activeCredentials"),
						fProto("ca_pubkey", 6, opt, tBytes, "", "caPubkey"),
						fProto("signature", 7, opt, tBytes, "", "signature"),
					},
				},
				{
					Name: proto.String("VerifiablePresentation"),
					Field: []*descriptorpb.FieldDescriptorProto{
						fProto("epoch_id", 1, opt, tUint64, "", "epochId"),
						fProto("namespace", 2, opt, tStr, "", "namespace"),
						fProto("peer_id", 3, opt, tStr, "", "peerId"),
						fProto("claims_commitment", 4, opt, tBytes, "", "claimsCommitment"),
						fProto("session_challenge", 5, opt, tBytes, "", "sessionChallenge"),
						fProto("challenge_tag", 6, opt, tBytes, "", "challengeTag"),
						fProto("timestamp", 7, opt, tInt64, "", "timestamp"),
						fProto("groth16_proof", 8, opt, tBytes, "", "groth16Proof"),
					},
				},
				{
					Name: proto.String("AuthReceipt"),
					Field: []*descriptorpb.FieldDescriptorProto{
						fProto("receipt_id", 1, opt, tBytes, "", "receiptId"),
						fProto("namespace", 2, opt, tStr, "", "namespace"),
						fProto("peer_id", 3, opt, tStr, "", "peerId"),
						fProto("claims_commitment", 4, opt, tBytes, "", "claimsCommitment"),
						fProto("epoch_id", 5, opt, tUint64, "", "epochId"),
						fProto("expires_at", 6, opt, tInt64, "", "expiresAt"),
						fProto("verifier_peer_id", 7, opt, tStr, "", "verifierPeerId"),
						fProto("verifier_signature", 8, opt, tBytes, "", "verifierSignature"),
					},
				},
				{
					Name: proto.String("VerifyResponse"),
					Field: []*descriptorpb.FieldDescriptorProto{
						fProto("valid", 1, opt, tBool, "", "valid"),
						fProto("error_message", 2, opt, tStr, "", "errorMessage"),
						fProto("receipt", 3, opt, tMsg, ".p2pauth.v1.AuthReceipt", "receipt"),
					},
				},
			},
		}

		rawDesc, err := proto.Marshal(fdp)
		if err != nil {
			panic(err)
		}

		type x struct{}
		out := protoimpl.TypeBuilder{
			File: protoimpl.DescBuilder{
				GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
				RawDescriptor: rawDesc,
				NumEnums:      1,
				NumMessages:   8,
				NumExtensions: 0,
				NumServices:   0,
			},
			GoTypes:           file_auth_proto_goTypes,
			DependencyIndexes: file_auth_proto_depIdxs,
			EnumInfos:         file_auth_proto_enumTypes,
			MessageInfos:      file_auth_proto_msgTypes,
		}.Build()
		File_auth_proto = out.File
		file_auth_proto_goTypes = nil
		file_auth_proto_depIdxs = nil
	})
}
