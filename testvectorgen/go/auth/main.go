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
	"test/crypto/primitive"
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

	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	var privKey babyjub.PrivateKey
	if _, err := hex.Decode(privKey[:], []byte(privKeyHex)); err != nil {
		panic(err)
	}

	claim, err := utils.AuthClaimFromPubKey(privKey.Public().X, privKey.Public().Y)

	identifier, claimsTree, revTree, currentState := createIdentityMultiAuthClaims(ctx, claim)

	authEntry := claim.TreeEntry()
	hIndex, err := authEntry.HIndex()
	utils.ExitOnError(err)
	proof, _, err := claimsTree.GenerateProof(ctx, hIndex.BigInt(), claimsTree.Root())
	utils.ExitOnError(err)
	allSiblingsClaimsTree := proof.AllSiblings()

	//MTP Claim not revoked
	revNonce := claim.GetRevocationNonce()
	revNonceInt := new(big.Int).SetUint64(revNonce)
	proofNotRevoke, _, err := revTree.GenerateProof(ctx, revNonceInt, revTree.Root())
	utils.ExitOnError(err)

	if proofNotRevoke.NodeAux == nil {
		inputs["authClaimNonRevMtpNoAux"] = "1"
		inputs["authClaimNonRevMtpAuxHi"] = "0"
		inputs["authClaimNonRevMtpAuxHv"] = "0"

	} else {
		inputs["authClaimNonRevMtpNoAux"] = "0"
		inputs["authClaimNonRevMtpAuxHi"] = proofNotRevoke.NodeAux.Key.BigInt().String()
		inputs["authClaimNonRevMtpAuxHv"] = proofNotRevoke.NodeAux.Value.BigInt().String()
	}

	challenge := big.NewInt(1)
	bjjSigner := primitive.NewBJJSigner(&privKey)
	signature, err := bjjSigner.Sign(challenge.Bytes())
	utils.ExitOnError(err)
	var sig [64]byte
	copy(sig[:], signature)
	var decompressedSig *babyjub.Signature
	decompressedSig, err = new(babyjub.Signature).Decompress(sig)
	utils.ExitOnError(err)

	inputs["id"] = identifier.BigInt().String()
	inputs["state"] = currentState.BigInt().String()

	for i := len(allSiblingsClaimsTree); i < 40; i++ {
		allSiblingsClaimsTree = append(allSiblingsClaimsTree, &merkletree.HashZero)
	}
	utils.PrintSiblings("authClaimMtp", allSiblingsClaimsTree)

	cs, err := utils.ClaimToString(claim)
	utils.ExitOnError(err)

	inputs["authClaim"] = cs

	nonRevSiblings := proofNotRevoke.AllSiblings()
	for i := len(nonRevSiblings); i < 40; i++ {
		nonRevSiblings = append(nonRevSiblings, &merkletree.HashZero)
	}

	utils.PrintSiblings("authClaimNonRevMtp", nonRevSiblings)

	inputs["claimsTreeRoot"] = claimsTree.Root().BigInt().String()
	inputs["revTreeRoot"] = revTree.Root().BigInt().String()
	inputs["rootsTreeRoot"] = merkletree.HashZero.String()

	inputs["challenge"] = challenge.String()
	inputs["challengeSignatureR8x"] = decompressedSig.R8.X.String()
	inputs["challengeSignatureR8y"] = decompressedSig.R8.Y.String()
	inputs["challengeSignatureS"] = decompressedSig.S.String()

	utils.PrintMap(inputs)

}

func createIdentityMultiAuthClaims(
	ctx context.Context, authClaim *core.Claim) (
	*core.ID, *merkletree.MerkleTree, *merkletree.MerkleTree, *merkletree.Hash) {
	claimTreeStorage := memory.NewMemoryStorage()
	claimsTree, err := merkletree.NewMerkleTree(ctx, claimTreeStorage, 40)
	utils.ExitOnError(err)

	var identifier *core.ID

	entry := authClaim.TreeEntry()
	err = claimsTree.AddEntry(ctx, &entry)
	utils.ExitOnError(err)
	identifier, err = core.CalculateGenesisID(claimsTree.Root())
	utils.ExitOnError(err)

	treeStorage := memory.NewMemoryStorage()
	revTree, err := merkletree.NewMerkleTree(ctx, treeStorage, 40)
	utils.ExitOnError(err)

	state, err := merkletree.HashElems(
		claimsTree.Root().BigInt(),
		revTree.Root().BigInt(),
		merkletree.HashZero.BigInt())
	utils.ExitOnError(err)

	return identifier, claimsTree, revTree, state
}
