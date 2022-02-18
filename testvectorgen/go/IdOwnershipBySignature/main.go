package main

import (
	"context"
	"encoding/hex"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"math/big"
	"test/utils"

	"test/crypto/primitive"
)

func main() {
	fmt.Println("\n-------\nNew identity test vectors:")

	privKeysHex := []string{
		"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f",
		"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e",
		"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d",
	}

	numberOfKeys := 2
	numberOfFirstClaimsToRevoke := 2
	signingKeyIndex := 1
	useRelay := true

	//claimSchema, _ := big.NewInt(0).SetString("251025091000101825075425831481271126140", 10)

	fmt.Println("Number of keys:", numberOfKeys)
	fmt.Println("Signing key index:", signingKeyIndex)
	fmt.Println("Number of first keys to revoke:", numberOfFirstClaimsToRevoke)
	fmt.Println("Use relay:", useRelay)

	privKeys := createPrivateKeys(privKeysHex[:numberOfKeys])
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
		utils.ExitOnError(err)
		hValue, err := authEntry.HValue()
		utils.ExitOnError(err)

		fmt.Println()
		fmt.Println("Claim info: ")
		fmt.Println(fmt.Sprintf("    Public key: %v, isSigningKey: %t, isRevokedKey: %t", i, isSigningKey, isRevokedKey))
		fmt.Println("    HIndex: ", hIndex.BigInt())
		fmt.Println("    HValue: ", hValue.BigInt())
		//fmt.Println("    Schema: ", claimSchema)
		fmt.Println("    x", v.Public().X)
		fmt.Println("    y", v.Public().Y)
		fmt.Println("    Revocation nonce: ", authClaims[i].GetRevocationNonce())
		//schema, err := authClaims[signingKeyIndex].GetSchemaHash().MarshalText()
		//fmt.Println("    GetSchemaHash: ", big.NewInt(0).SetBytes(schema))
	}

	ctx := context.Background()
	identifier, claimsTree, revTree, hoIdenState := createIdentityMultiAuthClaims(ctx, authClaims, numberOfFirstClaimsToRevoke)

	if useRelay {
		fmt.Println("\nhoId:", identifier.BigInt())
	} else {
		fmt.Println("hoIdenState:", hoIdenState.BigInt())
	}
	//MTP Claim
	fmt.Println("\nclaimsTreeRoot:", claimsTree.Root().BigInt())
	signingAuthClaim := authClaims[signingKeyIndex]
	authEntry := signingAuthClaim.TreeEntry()
	hIndex, err := authEntry.HIndex()
	utils.ExitOnError(err)
	proof, _, err := claimsTree.GenerateProof(ctx, hIndex.BigInt(), claimsTree.Root())
	utils.ExitOnError(err)
	allSiblingsClaimsTree := proof.AllSiblings()
	utils.PrintSiblings("authClaimMtp", allSiblingsClaimsTree)
	utils.PrintClaim("authClaim:", signingAuthClaim)

	//MTP Claim not revoked
	revNonce := signingAuthClaim.GetRevocationNonce()
	hi := new(big.Int).SetUint64(revNonce)
	proofNotRevoke, _, err := revTree.GenerateProof(ctx, hi, revTree.Root())
	utils.ExitOnError(err)

	fmt.Println("\nrevTreeRoot: ", revTree.Root().BigInt())
	utils.PrintSiblings("authClaimNonRevMtp:", proofNotRevoke.AllSiblings())
	if proofNotRevoke.NodeAux == nil {
		fmt.Println("authClaimNonRevMtpNoAux: 1")
		fmt.Println("authClaimNonRevMtpAuxHi: 0")
		fmt.Println("authClaimNonRevMtpAuxHv: 0")
	} else {
		fmt.Println("authClaimNonRevMtpNoAux: 0")
		fmt.Println("authClaimNonRevMtpAuxHi: ", proofNotRevoke.NodeAux.Key.BigInt())
		fmt.Println("authClaimNonRevMtpAuxHv: ", proofNotRevoke.NodeAux.Value.BigInt())
	}

	fmt.Println("\nrootsTreeRoot: 0")

	// Test signature
	challenge := big.NewInt(1)
	bjjSigner := primitive.NewBJJSigner(&privKeys[signingKeyIndex])
	signature, err := bjjSigner.Sign(challenge.Bytes())
	utils.ExitOnError(err)
	var sig [64]byte
	copy(sig[:], signature)
	var decompressedSig *babyjub.Signature
	decompressedSig, err = new(babyjub.Signature).Decompress(sig)
	utils.ExitOnError(err)

	fmt.Println("\nchallenge:", challenge)
	fmt.Println("challengeSignatureR8x:", decompressedSig.R8.X)
	fmt.Println("challengeSignatureR8y:", decompressedSig.R8.Y)
	fmt.Println("challengeSignatureS:", decompressedSig.S)

	if useRelay {
		idenStateInRelayClaim, reIdenState, relayClaimsTree, proofIdenStateInRelay := utils.GenerateRelayWithIdenStateClaim("28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c0000f", identifier, hoIdenState)

		fmt.Println("\nreIdenState:", reIdenState.BigInt())
		utils.PrintSiblings("hoStateInRelayClaimMtp:", proofIdenStateInRelay.AllSiblings())
		utils.PrintClaim("hoStateInRelayClaim:", idenStateInRelayClaim)
		fmt.Println("reProofValidClaimsTreeRoot:", relayClaimsTree.BigInt())
		fmt.Println("reProofValidRevTreeRoot: 0")
		fmt.Println("reProofValidRootsTreeRoot: 0")
	}
}

func createIdentityMultiAuthClaims(
	ctx context.Context, authClaims []*core.Claim, numOfFirstClaimsToRevoke int) (
	*core.ID, *merkletree.MerkleTree, *merkletree.MerkleTree, *merkletree.Hash) {
	claimTreeStorage := memory.NewMemoryStorage()
	claimsTree, err := merkletree.NewMerkleTree(ctx, claimTreeStorage, 4)
	utils.ExitOnError(err)

	var identifier *core.ID

	for i, claim := range authClaims {
		entry := claim.TreeEntry()
		err := claimsTree.AddEntry(ctx, &entry)
		utils.ExitOnError(err)
		if i == 0 {
			identifier, err = core.CalculateGenesisID(claimsTree.Root())
			utils.ExitOnError(err)
		}
	}

	revTree := createRevTree(ctx, authClaims[:numOfFirstClaimsToRevoke])

	state, err := utils.CalcIdentityStateFromRoots(claimsTree, revTree)
	utils.ExitOnError(err)

	return identifier, claimsTree, revTree, state
}

func createAuthClaims(privKeys []babyjub.PrivateKey) []*core.Claim {
	claims := make([]*core.Claim, len(privKeys))
	for i, v := range privKeys {
		pubKey := v.Public()
		claim, err := utils.AuthClaimFromPubKey(pubKey.X, pubKey.Y)
		utils.ExitOnError(err)
		claims[i] = claim
	}
	return claims
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
	utils.ExitOnError(err)

	for _, v := range authClaims {
		var err error

		revNonce := v.GetRevocationNonce()

		err = tree.Add(ctx, new(big.Int).SetUint64(revNonce), big.NewInt(0))
		utils.ExitOnError(err)
	}

	return tree
}
