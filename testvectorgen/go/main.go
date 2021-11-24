package main

import (
	"context"
	"encoding/hex"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"log"
	"math/big"
	"os"

	"test/crypto/primitive"
)

func main() {
	fmt.Println("\n-------\nNew identity test vectors:")
	privKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"

	// Extract pubKey
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	pk := k.Public()
	fmt.Println("x", pk.X)
	fmt.Println("y", pk.Y)

	// Create auth claim
	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("7c0844a075a9ddc7fcbdfb4f88acd9bc")
	copy(schemaHash[:], schemaEncodedBytes)

	authClaim, err := core.NewClaim(schemaHash,
		core.WithIndexDataInts(pk.X, pk.Y),
		//nolint:gosec //reason: no need for security
		core.WithRevocationNonce(uint64(0)))
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	treeStorage := memory.NewMemoryStorage()
	ctx := context.Background()
	claimsTree, err := merkletree.NewMerkleTree(ctx, treeStorage, 4)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	entry := authClaim.TreeEntry()
	claimsTree.AddEntry(ctx, &entry)

	fmt.Println("Claims claimsTree root Hex", claimsTree.Root().Hex())
	fmt.Println("Claims claimsTree root BigInt swapped", claimsTree.Root().BigInt())

	currentState, err := merkletree.HashElems(claimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(), merkletree.HashZero.BigInt())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	fmt.Println("Current state Hex", currentState)
	fmt.Println("Current state BigInt", currentState.BigInt())

	identifier, err := core.CalculateGenesisID(claimsTree.Root())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	fmt.Println("Identifier", identifier)
	// Test signature
	bjjSigner := primitive.NewBJJSigner(&k)
	signature, err := bjjSigner.Sign(big.NewInt(1).Bytes())

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	var sig [64]byte
	copy(sig[:], signature)
	var decompressedSig *babyjub.Signature
	decompressedSig, err = new(babyjub.Signature).Decompress(sig)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	fmt.Println("challengeSignatureR8x:", decompressedSig.R8.X.String())
	fmt.Println("challengeSignatureR8y", decompressedSig.R8.Y.String())
	fmt.Println("challengeSignatureS", decompressedSig.S.String())

	//inputs["BBJClaimRevTreeRoot"] = merkletree.HashZero
	//inputs["BBJClaimRootsTreeRoot"] = merkletree.HashZero

}
