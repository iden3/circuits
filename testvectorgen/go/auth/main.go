package main

import (
	"context"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"math/big"
	"test/utils"
)

/**
auth.circom

Generate test vectors for auth.circom
*/
func main() {
	fmt.Println("\n-------\nauth.circom test vector:")

	inputs := make(map[string]string)
	ctx := context.Background()

	challenge := new(big.Int).SetInt64(12345)
	privKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"

	// extract pubKey
	key, X, Y := utils.ExtractPubXY(privKHex)

	// init claims tree
	claimsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 4)
	utils.ExitOnError(err)

	// create auth claim
	authClaim, err := utils.AuthClaimFromPubKey(X, Y)
	utils.ExitOnError(err)

	// add auth claim to cMT
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

	inputs["id"] = identifier.BigInt().String()
	inputs["BBJAx"] = X.String()
	inputs["BBJAy"] = Y.String()
	inputs["BBJClaimClaimsTreeRoot"] = claimsTree.Root().BigInt().String()
	inputs["challenge"] = challenge.String()
	inputs["challengeSignatureR8x"] = decompressedSig.R8.X.String()
	inputs["challengeSignatureR8y"] = decompressedSig.R8.Y.String()
	inputs["challengeSignatureS"] = decompressedSig.S.String()
	inputs["state"] = currentState.BigInt().String()

	utils.PrintMap(inputs)

}
