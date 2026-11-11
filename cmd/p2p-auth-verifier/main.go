package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kevinpthorne/p2p-auth/pkg/circuit"
	"github.com/kevinpthorne/p2p-auth/pkg/cred"
	"github.com/kevinpthorne/p2p-auth/pkg/keystore"
	"github.com/kevinpthorne/p2p-auth/pkg/swarm"
)

func main() {
	port := flag.Int("port", 4006, "Libp2p TCP listen port")
	identityPath := flag.String("identity-key", "verifier-identity.key", "Verifier identity key file path")
	caPubPath := flag.String("ca-pub", "", "Path to trusted Root CA ML-DSA-87 public key")
	vkPath := flag.String("vk", "", "Optional path to Groth16 vk.bin")
	bootstrap := flag.String("bootstrap", "", "Comma-separated multiaddrs of Auth Server or swarm verifiers")
	flag.Parse()

	idKey, err := keystore.LoadOrInit(keystore.Options{
		KeyFilePath: *identityPath,
		AllowCreate: true,
		ForceTier:   keystore.TierFilesystem,
	})
	if err != nil {
		log.Fatalf("loading verifier identity: %v", err)
	}

	var caPub *cred.PublicKeyAlias
	if *caPubPath != "" {
		caPub, err = cred.LoadCAPublicKey(*caPubPath)
		if err != nil {
			log.Fatalf("loading CA public key: %v", err)
		}
	}

	var kb *circuit.KeyBundle
	if *vkPath != "" {
		kb, err = circuit.LoadKeys("", *vkPath)
	} else {
		kb, err = circuit.DefaultKeys()
	}
	if err != nil {
		log.Fatalf("loading Groth16 verifying key: %v", err)
	}

	var bootstrapAddrs []string
	for _, a := range strings.Split(*bootstrap, ",") {
		if trimmed := strings.TrimSpace(a); trimmed != "" {
			bootstrapAddrs = append(bootstrapAddrs, trimmed)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	vn, err := swarm.NewVerifierNode(ctx, swarm.Config{
		HostIdentity:   idKey,
		ListenAddr:     fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *port),
		BootstrapAddrs: bootstrapAddrs,
		TrustedCAPub:   caPub,
		VerifyingKey:   kb.VK,
	})
	if err != nil {
		log.Fatalf("starting VerifierNode: %v", err)
	}
	defer vn.Close()

	log.Printf("[p2p-auth-verifier] Swarm Verifier listening at %s", vn.Multiaddr())
	<-ctx.Done()
}
