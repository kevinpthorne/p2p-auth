package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kevinpthorne/p2p-auth/pkg/client"
	"github.com/kevinpthorne/p2p-auth/pkg/keystore"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: p2p-auth-client <adopt|prove|verify-swarm> [flags]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "adopt":
		fs := flag.NewFlagSet("adopt", flag.ExitOnError)
		serverAddr := fs.String("server", "", "Auth Server libp2p multiaddr")
		psk := fs.String("psk", os.Getenv("P2P_AUTH_ADOPTION_PSK"), "Adoption PSK token")
		namespace := fs.String("namespace", "default", "Application namespace")
		subjectID := fs.String("subject-id", "", "Node hostname / subject ID")
		stateDir := fs.String("state-dir", ".", "Directory to write credential.zkp, manifest.bin, and manifest.sig")
		keyPath := fs.String("identity-key", "identity.key", "Identity key file path")
		_ = fs.Parse(os.Args[2:])

		cl, err := client.NewClient(client.Config{
			Namespace:           *namespace,
			SubjectID:           *subjectID,
			StateDir:            *stateDir,
			AuthServerMultiaddr: *serverAddr,
			AdoptionPSK:         *psk,
			IdentityOpts: keystore.Options{
				KeyFilePath: *keyPath,
				AllowCreate: true,
			},
		})
		if err != nil {
			log.Fatalf("creating client: %v", err)
		}
		defer cl.Close()

		vc, err := cl.EnsureEnrolled(context.Background())
		if err != nil {
			log.Fatalf("adoption failed: %v", err)
		}
		fmt.Printf("Adopted & Enrolled: PeerID=%s Serial=%d Epoch=%d\n", cl.PeerID(), vc.SerialNumber, vc.EpochId)

	case "prove":
		fs := flag.NewFlagSet("prove", flag.ExitOnError)
		namespace := fs.String("namespace", "default", "Application namespace")
		stateDir := fs.String("state-dir", ".", "Directory containing credential.zkp")
		keyPath := fs.String("identity-key", "identity.key", "Identity key file path")
		verifierAddr := fs.String("verifier", "", "Optional Swarm Verifier multiaddr to request an AuthReceipt")
		disclose := fs.Bool("disclose-claims", true, "Disclose ClaimsCommitment in presentation")
		_ = fs.Parse(os.Args[2:])

		cl, err := client.NewClient(client.Config{
			Namespace:         *namespace,
			StateDir:          *stateDir,
			VerifierMultiaddr: *verifierAddr,
			IdentityOpts: keystore.Options{
				KeyFilePath: *keyPath,
			},
		})
		if err != nil {
			log.Fatalf("creating client: %v", err)
		}
		defer cl.Close()

		chal := make([]byte, 32)
		_, _ = rand.Read(chal)
		vp, err := cl.GenerateHandshakeProof(context.Background(), chal, *disclose)
		if err != nil {
			log.Fatalf("generating proof: %v", err)
		}
		fmt.Printf("Generated Groth16 VerifiablePresentation (%d bytes)\n", len(vp.Groth16Proof))

		if *verifierAddr != "" {
			receipt, err := cl.RequestSwarmTicket(context.Background(), vp)
			if err != nil {
				log.Fatalf("swarm verification failed: %v", err)
			}
			fmt.Printf("Verified by Swarm Peer %s -> Receipt ID %s (expires %d)\n",
				receipt.VerifierPeerId, hex.EncodeToString(receipt.ReceiptId), receipt.ExpiresAt)
		}
	}
}
