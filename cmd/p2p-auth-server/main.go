package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kevinpthorne/p2p-auth/pkg/circuit"
	"github.com/kevinpthorne/p2p-auth/pkg/cred"
	"github.com/kevinpthorne/p2p-auth/pkg/keystore"
	"github.com/kevinpthorne/p2p-auth/pkg/server"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "psk":
		cmdPSK(os.Args[2:])
	case "adopt":
		cmdAdopt(os.Args[2:])
	case "revoke":
		cmdRevoke(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: p2p-auth-server <subcommand> [flags]")
	fmt.Println("Subcommands:")
	fmt.Println("  init     Generate Root CA ML-DSA-87 keypair and Groth16 proving/verifying keys")
	fmt.Println("  serve    Start the Auth Server daemon, libp2p endpoints, and Web Admin UI")
	fmt.Println("  psk      Create or manage first-boot adoption PSK tokens")
	fmt.Println("  adopt    List or approve pending node adoption requests")
	fmt.Println("  revoke   Revoke an enrolled node by serial or Peer ID")
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	outDir := fs.String("out-dir", ".", "Directory to write ca.priv, ca.pub, pk.bin, and vk.bin")
	_ = fs.Parse(args)

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("creating output directory: %v", err)
	}

	pub, priv, err := cred.GenerateCAKeyPair()
	if err != nil {
		log.Fatalf("generating ML-DSA-87 keypair: %v", err)
	}
	privPath := filepath.Join(*outDir, "ca.priv")
	pubPath := filepath.Join(*outDir, "ca.pub")
	if err := cred.SaveCAKeyPair(privPath, pubPath, pub, priv); err != nil {
		log.Fatalf("saving CA keys: %v", err)
	}

	kb, err := circuit.Setup()
	if err != nil {
		log.Fatalf("generating Groth16 keys: %v", err)
	}
	pkPath := filepath.Join(*outDir, "pk.bin")
	vkPath := filepath.Join(*outDir, "vk.bin")
	if err := kb.SaveKeys(pkPath, vkPath); err != nil {
		log.Fatalf("saving Groth16 keys: %v", err)
	}

	fmt.Printf("Initialized p2p-auth CA and ZKP keys in %s\n", *outDir)
	fmt.Printf("  CA Key ID: %s\n", cred.ComputeCAKeyID(pub))
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	httpAddr := fs.String("http-addr", "0.0.0.0:8080", "HTTP REST & Web Admin UI listen address")
	p2pPort := fs.Int("p2p-port", 4005, "Libp2p TCP listen port")
	dbPath := fs.String("db", "auth.db", "Path to persistent state database")
	caPrivPath := fs.String("ca-priv", "", "Optional path to ca.priv")
	caPubPath := fs.String("ca-pub", "", "Optional path to ca.pub")
	identityPath := fs.String("identity-key", "server-identity.key", "Server libp2p identity key path")
	adminToken := fs.String("admin-token", os.Getenv("P2P_AUTH_ADMIN_TOKEN"), "Admin bearer token for Web UI and API")
	epochDuration := fs.Duration("epoch-duration", time.Hour, "Automatic epoch rotation interval")
	disableUI := fs.Bool("disable-ui", false, "Disable embedded Web Admin UI")
	tlsCert := fs.String("tls-cert", "", "Optional TLS certificate file")
	tlsKey := fs.String("tls-key", "", "Optional TLS private key file")
	_ = fs.Parse(args)

	var caPub, caPriv = loadOptionalCAKeys(*caPubPath, *caPrivPath)
	idKey, err := keystore.LoadOrInit(keystore.Options{
		KeyFilePath: *identityPath,
		AllowCreate: true,
		ForceTier:   keystore.TierFilesystem,
	})
	if err != nil {
		log.Fatalf("loading server identity key: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := server.NewAuthServer(ctx, server.Config{
		StorePath:     *dbPath,
		CAPubKey:      caPub,
		CAPrivKey:     caPriv,
		HostIdentity:  idKey,
		P2PListenAddr: fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *p2pPort),
		HTTPAddr:      *httpAddr,
		AdminToken:    *adminToken,
		EpochDuration: *epochDuration,
		DisableUI:     *disableUI,
		TLSCertFile:   *tlsCert,
		TLSKeyFile:    *tlsKey,
	})
	if err != nil {
		log.Fatalf("starting AuthServer: %v", err)
	}
	defer srv.Close()

	log.Printf("[p2p-auth-server] Listening on HTTP http://%s | Libp2p %s", srv.HTTPAddr(), srv.Multiaddr())
	<-ctx.Done()
}

func loadOptionalCAKeys(pubPath, privPath string) (pub *cred.PublicKeyAlias, priv *cred.PrivateKeyAlias) {
	if pubPath != "" && privPath != "" {
		p, err1 := cred.LoadCAPublicKey(pubPath)
		s, err2 := cred.LoadCAPrivateKey(privPath)
		if err1 == nil && err2 == nil {
			return p, s
		}
	}
	return nil, nil
}

func cmdPSK(args []string) {
	if len(args) == 0 || args[0] != "create" {
		log.Fatalf("Usage: p2p-auth-server psk create [flags]")
	}
	fs := flag.NewFlagSet("psk create", flag.ExitOnError)
	serverURL := fs.String("server-url", "http://127.0.0.1:8080", "Running p2p-auth-server HTTP URL")
	adminToken := fs.String("admin-token", os.Getenv("P2P_AUTH_ADMIN_TOKEN"), "Admin bearer token")
	namespace := fs.String("namespace", "default", "Application namespace")
	mode := fs.String("mode", "auto", "PSK mode: auto or queue")
	template := fs.String("manifest-template", "", "Opaque manifest template string or @filepath")
	domainCtx := fs.String("domain-context", cred.DefaultDomainContext, "ML-DSA-87 signing domain context")
	maxUses := fs.Int("max-uses", 1, "Maximum uses for this PSK")
	ttl := fs.Duration("ttl", 24*time.Hour, "PSK validity TTL")
	requireHW := fs.Bool("require-hw", false, "Require hardware keystore tier")
	_ = fs.Parse(args[1:])

	tplStr := *template
	if strings.HasPrefix(tplStr, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(tplStr, "@"))
		if err != nil {
			log.Fatalf("reading template file: %v", err)
		}
		tplStr = string(b)
	}

	reqBody, _ := json.Marshal(map[string]any{
		"namespace":             *namespace,
		"mode":                  strings.ToUpper(*mode),
		"domain_context":        *domainCtx,
		"manifest_template":     tplStr,
		"max_uses":              *maxUses,
		"ttl_hours":             int(ttl.Hours()),
		"require_hardware_tier": *requireHW,
	})

	resp := adminPost(*serverURL+"/api/admin/psks", *adminToken, reqBody)
	fmt.Println(string(resp))
}

func cmdAdopt(args []string) {
	if len(args) == 0 {
		log.Fatalf("Usage: p2p-auth-server adopt [list|approve]")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("adopt list", flag.ExitOnError)
		serverURL := fs.String("server-url", "http://127.0.0.1:8080", "Running p2p-auth-server HTTP URL")
		adminToken := fs.String("admin-token", os.Getenv("P2P_AUTH_ADMIN_TOKEN"), "Admin bearer token")
		_ = fs.Parse(args[1:])
		req, _ := http.NewRequest(http.MethodGet, *serverURL+"/api/admin/adopt/pending", nil)
		req.Header.Set("Authorization", "Bearer "+*adminToken)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("request failed: %v", err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		fmt.Println(string(b))

	case "approve":
		fs := flag.NewFlagSet("adopt approve", flag.ExitOnError)
		serverURL := fs.String("server-url", "http://127.0.0.1:8080", "Running p2p-auth-server HTTP URL")
		adminToken := fs.String("admin-token", os.Getenv("P2P_AUTH_ADMIN_TOKEN"), "Admin bearer token")
		manifestFile := fs.String("manifest-file", "", "Path to opaque manifest file")
		domainCtx := fs.String("domain-context", "", "Optional ML-DSA-87 domain context override")
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			log.Fatalf("Usage: p2p-auth-server adopt approve [flags] <peer-id|subject-id>")
		}
		target := fs.Arg(0)
		var manifestBytes []byte
		if *manifestFile != "" {
			var err error
			manifestBytes, err = os.ReadFile(*manifestFile)
			if err != nil {
				log.Fatalf("reading manifest file: %v", err)
			}
		}
		body, _ := json.Marshal(map[string]any{
			"peer_id":          target,
			"domain_context":   *domainCtx,
			"manifest_payload": string(manifestBytes),
		})
		resp := adminPost(*serverURL+"/api/admin/adopt/approve", *adminToken, body)
		fmt.Println(string(resp))
	}
}

func cmdRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	serverURL := fs.String("server-url", "http://127.0.0.1:8080", "Running p2p-auth-server HTTP URL")
	adminToken := fs.String("admin-token", os.Getenv("P2P_AUTH_ADMIN_TOKEN"), "Admin bearer token")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		log.Fatalf("Usage: p2p-auth-server revoke [flags] <peer-id|serial>")
	}
	target := fs.Arg(0)
	payload := map[string]any{}
	if serial, err := strconv.ParseUint(target, 10, 64); err == nil {
		payload["serial"] = serial
	} else {
		payload["peer_id"] = target
	}
	body, _ := json.Marshal(payload)
	resp := adminPost(*serverURL+"/api/admin/revoke", *adminToken, body)
	fmt.Println(string(resp))
}

func adminPost(url, token string, body []byte) []byte {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Fatalf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("admin request failed: %v", err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		log.Fatalf("server returned %d: %s", res.StatusCode, string(out))
	}
	return out
}
