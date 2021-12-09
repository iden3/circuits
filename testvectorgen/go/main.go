package main

import (
	"context"
	"encoding/hex"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"log"
	"math/big"
	"os"

	"test/crypto/primitive"
)

func main() {
	fmt.Println("\n-------\nNew identity test vectors:")

	privKeysHex := []string{
		"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f",
		"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e",
		//"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d",
		//"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69c",
		//"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69b",
		//"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69a",
	}

	numberOfFirstClaimsToRevoke := 2
	signingKeyIndex := 1

	fmt.Println()
	fmt.Println("signing with key ", signingKeyIndex)
	fmt.Println("numberOfFirstClaimsToRevoke ", numberOfFirstClaimsToRevoke)

	privKeys := createPrivateKeys(privKeysHex)
	authClaims := createAuthClaims(privKeys)

	for i, v := range privKeys {
		isSigningKey := false
		isRevokedKey := false
		if i == signingKeyIndex {
			isSigningKey = true
		}
		if i < numberOfFirstClaimsToRevoke {
			isRevokedKey = true
		}

		authEntry := authClaims[i].TreeEntry()
		hIndex, err := authEntry.HIndex()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		hValue, err := authEntry.HValue()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println("Claim info: ")
		fmt.Println(fmt.Sprintf("    Public key: %v, isSigningKey: %t, isRevokedKey: %t", i, isSigningKey, isRevokedKey))
		fmt.Println("    HIndex: ", hIndex.BigInt())
		fmt.Println("    HValue: ", hValue.BigInt())
		fmt.Println("    Schema: 251025091000101825075425831481271126140")
		fmt.Println("    x", v.Public().X)
		fmt.Println("    y", v.Public().Y)
		fmt.Println("    Revocation nonce: ", authClaims[i].GetRevocationNonce())
		//schema, err := authClaims[signingKeyIndex].GetSchemaHash().MarshalText()
		//fmt.Println("    GetSchemaHash: ", big.NewInt(0).SetBytes(schema))
	}

	ctx := context.Background()
	identifier, claimsTree, revTree, currentState := createIdentityMultiAuthClaims(ctx, authClaims, numberOfFirstClaimsToRevoke)

	fmt.Println()
	fmt.Println("id and hoId", identifier.BigInt())
	fmt.Println("hoIdenState", currentState.BigInt())
	fmt.Println()
	fmt.Println("claimsTreeRoot", claimsTree.Root().BigInt())
	fmt.Println("revTreeRoot", revTree.Root().BigInt())
	fmt.Println("rootsTreeRoot 0")

	authEntry := authClaims[signingKeyIndex].TreeEntry()
	hIndex, err := authEntry.HIndex()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	//MTP Claim
	proof, _, err := claimsTree.GenerateProof(ctx, hIndex.BigInt(), claimsTree.Root())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	allSiblings := proof.AllSiblings()
	fmt.Println("MTP proof all siblings: ")
	for _, v := range allSiblings {
		fmt.Println("     ", v.BigInt())
	}

	//MTP Not included
	//p, _, err := revTree.GenerateProof(ctx, hIndex.BigInt(), claimsTree.Root())

	// Test signature
	bjjSigner := primitive.NewBJJSigner(&privKeys[signingKeyIndex])
	challenge := big.NewInt(1)
	signature, err := bjjSigner.Sign(challenge.Bytes())

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

	fmt.Println()
	fmt.Println("challenge:", challenge)
	fmt.Println("challengeSignatureR8x:", decompressedSig.R8.X.String())
	fmt.Println("challengeSignatureR8y", decompressedSig.R8.Y.String())
	fmt.Println("challengeSignatureS", decompressedSig.S.String())

	//MTP Revoke
	revNonce := authClaims[signingKeyIndex].GetRevocationNonce()
	hi := new(big.Int).SetUint64(revNonce)
	proofNotRevoke, _, err := revTree.GenerateProof(ctx, hi, revTree.Root())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	fmt.Println("Rev nonce hIndex: ", hi)
	allSiblingsNotRevoke := proofNotRevoke.AllSiblings()
	if proofNotRevoke.NodeAux != nil {
		fmt.Println("revMtpAuxHi: ", proofNotRevoke.NodeAux.Key.BigInt())
		fmt.Println("revMtpAuxHv: ", proofNotRevoke.NodeAux.Value.BigInt())
	} else {
		fmt.Println("revMtpAuxHi: 0")
		fmt.Println("revMtpAuxHv: 0")
	}
	fmt.Println("MTP proof not revoke all siblings: ")
	for _, v := range allSiblingsNotRevoke {
		fmt.Println("    ", v.BigInt())
	}
}

func createIdentityMultiAuthClaims(
	ctx context.Context, authClaims []*core.Claim, numOfFirstClaimsToRevoke int) (
	*core.ID, *merkletree.MerkleTree, *merkletree.MerkleTree, *merkletree.Hash) {
	claimTreeStorage := memory.NewMemoryStorage()
	claimsTree, err := merkletree.NewMerkleTree(ctx, claimTreeStorage, 4)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	var identifier *core.ID

	for i, claim := range authClaims {
		entry := claim.TreeEntry()
		err := claimsTree.AddEntry(ctx, &entry)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		if i == 0 {
			identifier, err = core.CalculateGenesisID(claimsTree.Root())
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		}
	}

	revTree := createRevTree(ctx, authClaims[:numOfFirstClaimsToRevoke])

	state, err := merkletree.HashElems(
		claimsTree.Root().BigInt(),
		revTree.Root().BigInt(),
		merkletree.HashZero.BigInt())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	return identifier, claimsTree, revTree, state
}

func createAuthClaims(privKeys []babyjub.PrivateKey) []*core.Claim {
	claims := make([]*core.Claim, len(privKeys))
	for i, v := range privKeys {
		// NOTE: We take nonce as hash of public key to make it random
		// We don't use random number here because this test vectors will be used for tests
		// and have randomization inside tests is usually a bad idea
		revNonce, err := poseidon.Hash([]*big.Int{v.Public().X})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		claims[i] = createAuthClaim(v, revNonce.Uint64())
	}
	return claims
}

func createAuthClaim(privKey babyjub.PrivateKey, revNonce uint64) *core.Claim {
	// Extract pubKey
	pubKey := privKey.Public()

	// Create auth claim
	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("7c0844a075a9ddc7fcbdfb4f88acd9bc")
	copy(schemaHash[:], schemaEncodedBytes)

	authClaim, err := core.NewClaim(schemaHash,
		core.WithIndexDataInts(pubKey.X, pubKey.Y),
		//nolint:gosec //reason: no need for security
		core.WithRevocationNonce(revNonce))
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	return authClaim
}

func createPrivateKeys(privKeysHex []string) []babyjub.PrivateKey {
	privKeys := make([]babyjub.PrivateKey, len(privKeysHex))
	for i, v := range privKeysHex {
		privKeys[i] = createPrivateKey(v)
	}
	return privKeys
}

func createPrivateKey(privKeyHex string) babyjub.PrivateKey {
	var privKey babyjub.PrivateKey
	if _, err := hex.Decode(privKey[:], []byte(privKeyHex)); err != nil {
		panic(err)
	}
	return privKey
}

func createRevTree(ctx context.Context, authClaims []*core.Claim) *merkletree.MerkleTree {
	treeStorage := memory.NewMemoryStorage()
	tree, err := merkletree.NewMerkleTree(ctx, treeStorage, 4)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	for _, v := range authClaims {
		var err error

		revNonce := v.GetRevocationNonce()

		err = tree.Add(ctx, new(big.Int).SetUint64(revNonce), big.NewInt(0))
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}

	return tree
}
