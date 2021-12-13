package main

import (
	"context"
	"encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"math/big"
)

func main() {
	fmt.Println("\n-------\nauth.circom test vector:")

	inputs := make(map[string]string)
	ctx := context.Background()

	privKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"

	// Extract pubKey
	key, X, Y := ExtractPubXY(privKHex)
	inputs["BBJAx"] = X.String()
	inputs["BBJAy"] = Y.String()

	claimsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 4)
	exitOnError(err)

	authClaim, err := AuthClaimFromPubKey(X, Y)
	exitOnError(err)

	entry := authClaim.TreeEntry()
	hi, hv, err := entry.HiHv()
	exitOnError(err)
	claimsTree.Add(ctx, hi.BigInt(), hv.BigInt())

	inputs["BBJClaimClaimsTreeRoot"] = claimsTree.Root().BigInt().String()

	challenge := new(big.Int).SetInt64(12345)
	inputs["challenge"] = challenge.String()

	decompressedSig, err := SignatureInputs(key, challenge.Bytes())
	exitOnError(err)

	inputs["challengeSignatureR8x"] = decompressedSig.R8.X.String()
	inputs["challengeSignatureR8y"] = decompressedSig.R8.Y.String()
	inputs["challengeSignatureS"] = decompressedSig.S.String()

	identifier, err := core.CalculateGenesisID(claimsTree.Root())
	exitOnError(err)

	inputs["id"] = identifier.BigInt().String()

	// calculate current state
	currentState, err := merkletree.HashElems(claimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(), merkletree.HashZero.BigInt())
	exitOnError(err)

	inputs["state"] = currentState.BigInt().String()

	json, err := json.Marshal(inputs)
	exitOnError(err)
	fmt.Println(string(json))

}
