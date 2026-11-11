package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type KeystoreTier string

const (
	TierTPM2          KeystoreTier = "TPM2.0"
	TierSecureEnclave KeystoreTier = "AppleSecureEnclave"
	TierFilesystem    KeystoreTier = "Filesystem"

	EncryptedKeyPEMType = "ENCRYPTED P2P AUTH KEY"

	pbkdf2Iterations = 210000
	pbkdf2SaltSize   = 16
	gcmNonceSize     = 12
	aesKeySize       = 32
	envelopeVersion  = 0x01
)

var (
	ErrPassphraseRequired = errors.New("encrypted key requires a passphrase (set Options.Passphrase or P2P_AUTH_KEY_PASSPHRASE)")
	ErrDecryptionFailed   = errors.New("failed to decrypt key: invalid passphrase or corrupted ciphertext")
)

// IdentityKey encapsulates a node's persistent cryptographic identity.
type IdentityKey struct {
	tier       KeystoreTier
	libp2pPriv ic.PrivKey
	peerID     peer.ID
}

func (k *IdentityKey) Tier() KeystoreTier       { return k.tier }
func (k *IdentityKey) Libp2pPrivKey() ic.PrivKey { return k.libp2pPriv }
func (k *IdentityKey) PeerID() peer.ID           { return k.peerID }

type Options struct {
	KeyFilePath string
	AllowCreate bool
	ForceTier   KeystoreTier
	Passphrase  string
}

func resolvePassphrase(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("P2P_AUTH_KEY_PASSPHRASE"); env != "" {
		return env
	}
	if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		if data, err := os.ReadFile(filepath.Join(credDir, "key.passphrase")); err == nil {
			return strings.TrimRight(string(data), "\r\n")
		}
	}
	return ""
}

func DeriveKeyPBKDF2(passphrase, salt []byte, iterations, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	var blockBuf [4]byte

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
		in := make([]byte, len(salt)+4)
		copy(in, salt)
		copy(in[len(salt):], blockBuf[:])

		u := prf(passphrase, in)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 2; i <= iterations; i++ {
			u = prf(passphrase, u)
			subtle.XORBytes(t, t, u)
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func EncryptBytesWithPassphrase(plaintext []byte, passphrase string, pemType string) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("cannot encrypt empty key material")
	}
	if passphrase == "" {
		return nil, ErrPassphraseRequired
	}

	salt := make([]byte, pbkdf2SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating PBKDF2 salt: %w", err)
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating AES-GCM nonce: %w", err)
	}

	kek := DeriveKeyPBKDF2([]byte(passphrase), salt, pbkdf2Iterations, aesKeySize)
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()

	aesBlock, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("initializing AES-256 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("initializing AES-256-GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(pemType))
	envelope := make([]byte, 1+pbkdf2SaltSize+gcmNonceSize+len(ciphertext))
	envelope[0] = envelopeVersion
	copy(envelope[1:1+pbkdf2SaltSize], salt)
	copy(envelope[1+pbkdf2SaltSize:1+pbkdf2SaltSize+gcmNonceSize], nonce)
	copy(envelope[1+pbkdf2SaltSize+gcmNonceSize:], ciphertext)

	pemBlock := &pem.Block{
		Type: pemType,
		Headers: map[string]string{
			"KDF":    "PBKDF2-HMAC-SHA256",
			"Cipher": "AES-256-GCM",
		},
		Bytes: envelope,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func DecryptBytesWithPassphrase(pemData []byte, passphrase string, expectedPEMType string) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != expectedPEMType {
		return nil, fmt.Errorf("invalid PEM block: expected %q", expectedPEMType)
	}
	if passphrase == "" {
		return nil, ErrPassphraseRequired
	}

	minLen := 1 + pbkdf2SaltSize + gcmNonceSize + 16
	if len(block.Bytes) < minLen {
		return nil, ErrDecryptionFailed
	}
	if block.Bytes[0] != envelopeVersion {
		return nil, fmt.Errorf("unsupported encrypted key envelope version: 0x%02x", block.Bytes[0])
	}

	salt := block.Bytes[1 : 1+pbkdf2SaltSize]
	nonce := block.Bytes[1+pbkdf2SaltSize : 1+pbkdf2SaltSize+gcmNonceSize]
	ciphertext := block.Bytes[1+pbkdf2SaltSize+gcmNonceSize:]

	kek := DeriveKeyPBKDF2([]byte(passphrase), salt, pbkdf2Iterations, aesKeySize)
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()

	aesBlock, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("initializing AES-256 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("initializing AES-256-GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(expectedPEMType))
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// LoadOrInit loads or generates a node identity following the hardware waterfall:
// Tier 1A (TPM 2.0) -> Tier 1B (Apple Secure Enclave) -> Tier 2 (Filesystem).
func LoadOrInit(opts Options) (*IdentityKey, error) {
	passphrase := resolvePassphrase(opts.Passphrase)

	if opts.KeyFilePath != "" && isInlineKey(opts.KeyFilePath) {
		priv, err := tryFilesystem(opts.KeyFilePath, false, passphrase)
		if err != nil {
			return nil, fmt.Errorf("loading inline identity key: %w", err)
		}
		return buildIdentity(priv, TierFilesystem)
	}

	if opts.ForceTier == TierFilesystem {
		keyPath := opts.KeyFilePath
		if keyPath == "" {
			keyPath = "identity.key"
		}
		priv, err := tryFilesystem(keyPath, opts.AllowCreate, passphrase)
		if err != nil {
			return nil, fmt.Errorf("loading filesystem identity key (%s): %w", keyPath, err)
		}
		return buildIdentity(priv, TierFilesystem)
	}

	if opts.ForceTier == "" || opts.ForceTier == TierTPM2 {
		if tpmKey, err := tryTPM2(); err == nil && tpmKey != nil {
			return buildIdentityFromECDSA(tpmKey, TierTPM2)
		} else if opts.ForceTier == TierTPM2 {
			return nil, fmt.Errorf("TPM 2.0 forced but unavailable: %w", err)
		}
	}

	if opts.ForceTier == "" || opts.ForceTier == TierSecureEnclave {
		if seKey, err := trySecureEnclave(); err == nil && seKey != nil {
			return buildIdentityFromECDSA(seKey, TierSecureEnclave)
		} else if opts.ForceTier == TierSecureEnclave {
			return nil, fmt.Errorf("Secure Enclave forced but unavailable: %w", err)
		}
	}

	if envKey := strings.TrimSpace(os.Getenv("P2P_AUTH_IDENTITY_KEY")); envKey != "" {
		priv, err := tryFilesystem(envKey, opts.AllowCreate, passphrase)
		if err != nil {
			return nil, fmt.Errorf("loading identity key from P2P_AUTH_IDENTITY_KEY: %w", err)
		}
		return buildIdentity(priv, TierFilesystem)
	}

	keyPath := opts.KeyFilePath
	if keyPath == "" {
		keyPath = "identity.key"
	}
	priv, err := tryFilesystem(keyPath, opts.AllowCreate, passphrase)
	if err != nil {
		return nil, fmt.Errorf("no persistent identity key found (TPM/SE unavailable, and %s could not be loaded): %w", keyPath, err)
	}
	return buildIdentity(priv, TierFilesystem)
}

// GenerateEphemeralIdentity generates an in-memory ECDSA P-256 identity key (matching hardware TPM/SE curve).
func GenerateEphemeralIdentity() (*IdentityKey, error) {
	priv, _, err := ic.GenerateKeyPair(ic.ECDSA, 256)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral ECDSA P-256 key: %w", err)
	}
	return buildIdentity(priv, TierFilesystem)
}

func buildIdentity(priv ic.PrivKey, tier KeystoreTier) (*IdentityKey, error) {
	pID, err := peer.IDFromPublicKey(priv.GetPublic())
	if err != nil {
		return nil, fmt.Errorf("deriving Peer ID from public key: %w", err)
	}
	return &IdentityKey{
		tier:       tier,
		libp2pPriv: priv,
		peerID:     pID,
	}, nil
}

func buildIdentityFromECDSA(key *ecdsa.PrivateKey, tier KeystoreTier) (*IdentityKey, error) {
	p2pPriv, _, err := ic.ECDSAKeyPairFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("wrapping ECDSA anchor key as libp2p identity: %w", err)
	}
	return buildIdentity(p2pPriv, tier)
}

func tryTPM2() (*ecdsa.PrivateKey, error) {
	devices := []string{"/dev/tpmrm0", "/dev/tpm0"}
	var lastErr error
	for _, dev := range devices {
		rwc, err := tpm2.OpenTPM(dev)
		if err != nil {
			lastErr = err
			continue
		}
		key, kErr := deriveIdentityFromTPM(rwc)
		_ = rwc.Close()
		if kErr == nil && key != nil {
			return key, nil
		}
		lastErr = kErr
	}
	if lastErr != nil {
		return nil, fmt.Errorf("no TPM 2.0 device usable: %w", lastErr)
	}
	return nil, errors.New("no TPM 2.0 device accessible")
}

func deriveIdentityFromTPM(rw io.ReadWriter) (*ecdsa.PrivateKey, error) {
	uniqueSeed := sha256.Sum256([]byte("p2p-auth:tpm2:primary-template:v1"))
	primaryTemplate := tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: uniqueSeed[:],
				YRaw: uniqueSeed[:],
			},
		},
	}

	handle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", primaryTemplate)
	if err != nil {
		return nil, fmt.Errorf("TPM2_CreatePrimary failed: %w", err)
	}
	defer func() {
		_ = tpm2.FlushContext(rw, handle)
	}()

	curve := elliptic.P256()
	gx, gy := curve.ScalarBaseMult([]byte{0x02})
	zPoint, err := tpm2.ECDHZGen(rw, handle, "", tpm2.ECPoint{
		XRaw: gx.Bytes(),
		YRaw: gy.Bytes(),
	})
	if err != nil {
		return nil, fmt.Errorf("TPM2_ECDH_ZGen failed: %w", err)
	}

	mac := hmac.New(sha256.New, []byte("p2p-auth:tpm2:identity:v1"))
	mac.Write(zPoint.XRaw)
	mac.Write(zPoint.YRaw)
	digest := mac.Sum(nil)

	order := curve.Params().N
	one := big.NewInt(1)
	d := new(big.Int).SetBytes(digest)
	d.Mod(d, new(big.Int).Sub(order, one))
	d.Add(d, one)

	pubX, pubY := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     pubX,
			Y:     pubY,
		},
		D: d,
	}, nil
}

func trySecureEnclave() (*ecdsa.PrivateKey, error) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return nil, errors.New("Secure Enclave only supported on Darwin ARM64")
	}
	return nil, errors.New("Secure Enclave not available in current process context")
}

func isInlineKey(s string) bool {
	trimmed := strings.TrimSpace(s)
	if strings.Contains(trimmed, "-----BEGIN") {
		return true
	}
	if b64, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(b64) > 0 {
		if _, err := ic.UnmarshalPrivateKey(b64); err == nil {
			return true
		}
	}
	return false
}

func parsePrivateKey(data []byte, passphrase string) (ic.PrivKey, error) {
	trimmedStr := strings.TrimSpace(string(data))
	if strings.Contains(trimmedStr, "-----BEGIN "+EncryptedKeyPEMType+"-----") {
		decrypted, err := DecryptBytesWithPassphrase(data, passphrase, EncryptedKeyPEMType)
		if err != nil {
			return nil, err
		}
		defer func() {
			for i := range decrypted {
				decrypted[i] = 0
			}
		}()
		return parseUnencryptedPrivateKey(decrypted)
	}
	return parseUnencryptedPrivateKey(data)
}

func parseUnencryptedPrivateKey(data []byte) (ic.PrivKey, error) {
	if priv, err := ic.UnmarshalPrivateKey(data); err == nil {
		return priv, nil
	}
	trimmedStr := strings.TrimSpace(string(data))
	if b64, err := base64.StdEncoding.DecodeString(trimmedStr); err == nil && len(b64) > 0 {
		if priv, err := ic.UnmarshalPrivateKey(b64); err == nil {
			return priv, nil
		}
	}
	if strings.Contains(trimmedStr, "-----BEGIN") {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("invalid PEM data")
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			p2pPriv, _, err := ic.ECDSAKeyPairFromKey(key)
			return p2pPriv, err
		}
		if pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey); ok {
				p2pPriv, _, err := ic.ECDSAKeyPairFromKey(ecKey)
				return p2pPriv, err
			}
		}
	}
	return nil, errors.New("unrecognized identity key format")
}

func tryFilesystem(pathOrData string, allowCreate bool, passphrase string) (ic.PrivKey, error) {
	trimmed := strings.TrimSpace(pathOrData)
	if trimmed == "" {
		return nil, errors.New("empty identity key path or data")
	}
	if isInlineKey(trimmed) {
		return parsePrivateKey([]byte(trimmed), passphrase)
	}

	data, err := os.ReadFile(trimmed)
	if err == nil {
		return parsePrivateKey(data, passphrase)
	}

	if !allowCreate || !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading key file %q: %w", trimmed, err)
	}

	// Default to ECDSA P-256 on filesystem creation to match hardware TPM/SE tier
	priv, _, err := ic.GenerateKeyPair(ic.ECDSA, 256)
	if err != nil {
		return nil, fmt.Errorf("generating libp2p ECDSA P-256 key: %w", err)
	}
	keyBytes, err := ic.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshaling libp2p private key: %w", err)
	}

	outBytes := keyBytes
	if passphrase != "" {
		encrypted, encErr := EncryptBytesWithPassphrase(keyBytes, passphrase, EncryptedKeyPEMType)
		if encErr != nil {
			return nil, fmt.Errorf("encrypting identity key at rest: %w", encErr)
		}
		outBytes = encrypted
	}

	if dir := filepath.Dir(trimmed); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(trimmed, outBytes, 0600); err != nil {
		return nil, fmt.Errorf("writing key file %q: %w", trimmed, err)
	}
	return priv, nil
}
