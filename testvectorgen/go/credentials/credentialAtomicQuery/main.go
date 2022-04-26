package main

import (
	"context"
	"encoding/hex"
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

	// Generate inputs for credentialAtomicQueryMTPWithRelay.circom and credentialAtomicQueryMTP.circom
	attributeQuery()
}

func attributeQuery() {
	fmt.Println("\n-------\ntest vectors for credentialAtomicQuery:")
	userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	relayPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c40000"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(12345)

	ctx := context.Background()

	// User
	userIdentity, userClaimsTree, userInputs := utils.GenerateIdentity(ctx, userPrivKHex, challenge)

	// Relay
	userState, _ := utils.CalcIdentityStateFromRoots(userClaimsTree)

	idenStateInRelayClaim, reIdenState, relayClaimsTreeRoot, proofIdenStateInRelay := utils.GenerateRelayWithIdenStateClaim(
		relayPrivKHex, userIdentity, userState)

	fmt.Println("\nreIdenState", reIdenState.BigInt())
	utils.PrintSiblings("hoStateInRelayClaimMtp:", proofIdenStateInRelay.AllSiblings())
	utils.PrintClaim("hoStateInRelayClaim:", idenStateInRelayClaim)
	fmt.Println("reProofValidClaimsTreeRoot:", relayClaimsTreeRoot.BigInt())
	fmt.Println("reProofValidRevTreeRoot: 0")
	fmt.Println("reProofValidRootsTreeRoot: 0")

	// Issuer
	_, issuerClaimsTree, issuerInputs := utils.GenerateIdentity(ctx, issuerPrivKHex, challenge)

	fmt.Println("\nUser inputs:")
	utils.PrintMap(userInputs)
	fmt.Println("Issuer inputs:")
	utils.PrintMap(issuerInputs)

	// issue claim for user
	dataSlotA, _ := core.NewElemBytesFromInt(big.NewInt(10))
	nonce := 1
	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	copy(schemaHash[:], schemaBytes)

	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*userIdentity),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	utils.ExitOnError(err)

	// addClaimToIssuerTree
	proof, err := utils.AddClaimToTree(issuerClaimsTree, claim)
	utils.ExitOnError(err)

	// Calim proof
	proofSib, err := json.Marshal(proof.AllSiblings())
	utils.ExitOnError(err)

	fmt.Println("\nproofSib:", string(proofSib))

	claimAsString := utils.ClaimToString(claim)

	fmt.Println("claimAsString:", claimAsString)

	fmt.Println("issuer claim tree root:", issuerClaimsTree.Root().BigInt().String())
	fmt.Println("current issuer state:")
	utils.PrintCurrentState(issuerClaimsTree)

	issuerRevTreeStorage := memory.NewMemoryStorage()
	issuerRevTree, err := merkletree.NewMerkleTree(ctx, issuerRevTreeStorage, 4)
	utils.ExitOnError(err)

	generateProof, _, err := issuerRevTree.GenerateProof(context.TODO(), big.NewInt(int64(nonce)), issuerRevTree.Root())
	utils.ExitOnError(err)

	//Revocation proof inputs
	fmt.Println("Revocation 1 proofs")
	marshal, err := json.Marshal(generateProof.AllSiblings())
	utils.ExitOnError(err)

	fmt.Println("Marshaled all siblings", string(marshal))

	fmt.Println("existence:", generateProof.Existence)
	fmt.Println("NodeAux ", generateProof.NodeAux)
	//fmt.Println("NodeAux Key:",proof.NodeAux.Key.BigInt().String())
	//fmt.Println("NodeAux Value:",proof.NodeAux.Value.BigInt().String())

	fmt.Println("Rev tree state:", issuerClaimsTree.Root().BigInt().String())
	fmt.Println("Rev tree issuer state:")
	utils.PrintCurrentState(issuerClaimsTree)

}
