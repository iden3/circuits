package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
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

	useRelay := true

	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	var privKey babyjub.PrivateKey
	if _, err := hex.Decode(privKey[:], []byte(privKeyHex)); err != nil {
		panic(err)
	}

	claim, err := utils.AuthClaimFromPubKey(privKey.Public().X, privKey.Public().Y)

	identifier, claimsTree, revTree, currentState := createIdentityMultiAuthClaims(ctx, claim)

	hIndex, err := claim.HIndex()
	utils.ExitOnError(err)
	proof, _, err := claimsTree.GenerateProof(ctx, hIndex, claimsTree.Root())
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

	inputs["userID"] = identifier.BigInt().String()
	inputs["state"] = currentState.BigInt().String()

	for i := len(allSiblingsClaimsTree); i < 40; i++ {
		allSiblingsClaimsTree = append(allSiblingsClaimsTree, &merkletree.HashZero)
	}
	utils.PrintSiblings("authClaimMtp", allSiblingsClaimsTree)

	cs := utils.ClaimToString(claim)

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

	if useRelay {
		userStateInRelayClaim, relayState, relayClaimsTree, proofIdenStateInRelay := utils.GenerateRelayWithIdenStateClaim(
			"9db637b457c284e844e58955c54cd8e67d989b72ed4b56411eabbeb775fb853a", identifier, currentState)

		fmt.Println("\nrelayState:", relayState.BigInt())
		utils.PrintSiblings("userStateInRelayClaimMtp:", proofIdenStateInRelay.AllSiblings())
		utils.PrintClaim("userStateInRelayClaim:", userStateInRelayClaim)
		fmt.Println("relayProofValidClaimsTreeRoot:", relayClaimsTree.BigInt())
		fmt.Println("relayProofValidRevTreeRoot: 0")
		fmt.Println("relayProofValidRootsTreeRoot: 0")
	}
}

func createIdentityMultiAuthClaims(
	ctx context.Context, authClaim *core.Claim) (
	*core.ID, *merkletree.MerkleTree, *merkletree.MerkleTree, *merkletree.Hash) {
	claimTreeStorage := memory.NewMemoryStorage()
	claimsTree, err := merkletree.NewMerkleTree(ctx, claimTreeStorage, 40)
	utils.ExitOnError(err)

	var identifier *core.ID

	hi, hv, err := authClaim.HiHv()
	utils.ExitOnError(err)
	err = claimsTree.Add(ctx, hi, hv)
	utils.ExitOnError(err)

	state, err := core.IdenState(claimsTree.Root().BigInt(), big.NewInt(0), big.NewInt(0))
	utils.ExitOnError(err)

	identifier, err = core.IdGenesisFromIdenState(core.TypeDefault, state)
	utils.ExitOnError(err)

	treeStorage := memory.NewMemoryStorage()
	revTree, err := merkletree.NewMerkleTree(ctx, treeStorage, 40)
	utils.ExitOnError(err)

	stateHash, err := merkletree.HashElems(
		claimsTree.Root().BigInt(),
		revTree.Root().BigInt(),
		merkletree.HashZero.BigInt())
	utils.ExitOnError(err)

	return identifier, claimsTree, revTree, stateHash
}
