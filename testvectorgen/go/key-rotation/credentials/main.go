package main

import (
	"context"
	"encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"math/big"
	"test/utils"
	"time"
)

func main() {
	fmt.Println("\n-------\nTest vectors for credentials.circom:")
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(12345)

	ctx := context.Background()

	// Holder
	userIdentity, holderClaimsTree, holderInputs := generateIdentity(ctx, userPrivKHex, challenge)
	fmt.Println("\nholderClaimsTree:", holderClaimsTree)
	fmt.Println("\nholderInputs:")
	utils.PrintMap(holderInputs)

	// Issuer
	_, issuerClaimsTree, issuerInputs := generateIdentity(ctx, issuerPrivKHex, challenge)
	fmt.Println("\nissuerInputs:")
	utils.PrintMap(issuerInputs)

	fmt.Println("\nhoId:", userIdentity.BigInt())

	// issue claim for holder
	dataSlotA, _ := core.NewDataSlotFromInt(big.NewInt(10))
	nonce := 1
	var schemaHash core.SchemaHash
	copy(schemaHash[:], "1")
	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*userIdentity),
		core.WithIndexData(dataSlotA, core.DataSlot{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	utils.ExitOnError(err)
	proof, err := utils.AddClaimToTree(issuerClaimsTree, claim)
	utils.ExitOnError(err)
	claimAsString, err := utils.ClaimToString(claim)
	utils.ExitOnError(err)
	fmt.Println("\nclaim:", claimAsString)
	fmt.Println("isProofExistClaimsTreeRoot:", issuerClaimsTree.Root().BigInt().String())
	proofSib, err := json.Marshal(proof.AllSiblings())
	utils.ExitOnError(err)
	fmt.Println("isProofExistsMtp:", string(proofSib))

	fmt.Println("\nisProofValidClaimsTreeRoot:", issuerClaimsTree.Root().BigInt().String())

	issuerRevTreeStorage := memory.NewMemoryStorage()
	issuerRevTree, err := merkletree.NewMerkleTree(ctx, issuerRevTreeStorage, 4)
	utils.ExitOnError(err)
	fmt.Println("\nisProofValidRevTreeRoot:", issuerRevTree.Root().BigInt().String())
	claimNonRevProof, _, err := issuerRevTree.GenerateProof(context.TODO(), big.NewInt(int64(nonce)), issuerRevTree.Root())
	utils.ExitOnError(err)
	utils.PrintSiblings("isProofValidNonRevMtp", claimNonRevProof.AllSiblings())
	if claimNonRevProof.NodeAux == nil {
		fmt.Println("isProofValidNonRevMtpNoAux: 1")
		fmt.Println("isProofValidNonRevMtpAuxHi: 0")
		fmt.Println("isProofValidNonRevMtpAuxHi: 0")
	} else {
		fmt.Println("isProofValidNonRevMtpNoAux: 0")
		fmt.Println("isProofValidNonRevMtpAuxHi: ", claimNonRevProof.NodeAux.Key.BigInt())
		fmt.Println("isProofValidNonRevMtpAuxHi: ", claimNonRevProof.NodeAux.Value.BigInt())
	}

	// Add Claims Tree Root to Roots Tree
	issuerRootsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 4)
	utils.ExitOnError(err)
	err = issuerRootsTree.Add(context.TODO(), issuerClaimsTree.Root().BigInt(), big.NewInt(0))
	utils.ExitOnError(err)
	proofClaimsTreeRootInRootsTree, _, err := issuerRootsTree.GenerateProof(context.TODO(), issuerClaimsTree.Root().BigInt(), nil)
	utils.ExitOnError(err)
	fmt.Println("\nisProofValidRootsTreeRoot:", issuerRootsTree.Root().BigInt())
	fmt.Println("isProofRootMtp:", proofClaimsTreeRootInRootsTree.AllSiblings())

	currentState, err := merkletree.HashElems(issuerClaimsTree.Root().BigInt(),
		issuerRevTree.Root().BigInt(), issuerRootsTree.Root().BigInt())
	utils.ExitOnError(err)
	fmt.Println("\nisIdenState::", currentState.BigInt())
}

func generateIdentity(ctx context.Context, privKHex string, challenge *big.Int) (*core.ID, *merkletree.MerkleTree, map[string]string) {

	// extract pubKey
	key, X, Y := utils.ExtractPubXY(privKHex)

	// init claims tree
	claimsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 4)
	utils.ExitOnError(err)

	// create auth claim
	authClaim, err := utils.AuthClaimFromPubKey(X, Y)
	utils.ExitOnError(err)

	// add auth claim to claimsMT
	entry := authClaim.TreeEntry()
	hi, hv, err := entry.HiHv()
	utils.ExitOnError(err)
	claimsTree.Add(ctx, hi.BigInt(), hv.BigInt())

	// sign challenge
	decompressedSig, err := utils.SignBBJJ(key, challenge.Bytes())
	utils.ExitOnError(err)

	// create new identity
	identifier, err := core.CalculateGenesisID(claimsTree.Root())
	utils.ExitOnError(err)

	// calculate current state
	currentState, err := merkletree.HashElems(claimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(), merkletree.HashZero.BigInt())
	utils.ExitOnError(err)

	inputs := make(map[string]string)
	inputs["id"] = identifier.BigInt().String()
	inputs["BBJAx"] = X.String()
	inputs["BBJAy"] = Y.String()
	inputs["BBJClaimClaimsTreeRoot"] = claimsTree.Root().BigInt().String()
	inputs["challenge"] = challenge.String()
	inputs["challengeSignatureR8x"] = decompressedSig.R8.X.String()
	inputs["challengeSignatureR8y"] = decompressedSig.R8.Y.String()
	inputs["challengeSignatureS"] = decompressedSig.S.String()
	inputs["state"] = currentState.BigInt().String()

	return identifier, claimsTree, inputs
}
