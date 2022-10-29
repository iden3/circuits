package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"test/crypto/primitive"
	"test/utils"
)

func main() {

	// Generate inputs for credentialAtomicQueryMTP.circom
	attributeQuery()
}

func attributeQuery() {
	fmt.Println("\n-------\ntest vectors for credentialAtomicQuery:")
	//userPrivKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	issuerPrivKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"
	challenge := new(big.Int).SetInt64(12345)

	ctx := context.Background()

	// User
	//userIdentity, _, userInputs := utils.GenerateIdentity(ctx, userPrivKHex, challenge)
	userIDInt, _ := new(big.Int).SetString(
		"20920305170169595198233610955511031459141100274346276665183631177096036352", 10)
	userIdentity, _ := core.IDFromInt(userIDInt)

	// Issuer
	_, issuerClaimsTree, issuerInputs := utils.GenerateIdentity(ctx, issuerPrivKHex, challenge)

	fmt.Println("\nUser inputs:")
	//utils.PrintMap(userInputs)
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
		core.WithIndexID(userIdentity),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	utils.ExitOnError(err)

	// sign claim
	sig, err := signClaim(issuerPrivKHex, claim)
	if err != nil {
		panic(err)
	}
	fmt.Println("issuerClaimSignatureR8x", sig.R8.X.String())
	fmt.Println("issuerClaimSignatureR8y", sig.R8.Y.String())
	fmt.Println("issuerClaimSignatureS", sig.S.String())

	// addClaimToIssuerTree
	proof, err := utils.AddClaimToTree(issuerClaimsTree, claim)
	utils.ExitOnError(err)

	// Calim proof
	proofSib, err := json.Marshal(proof.AllSiblings())
	utils.ExitOnError(err)

	fmt.Println("\nproofSib exist:", string(proofSib))

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
	issuerState, err := merkletree.HashElems(issuerClaimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(), merkletree.HashZero.BigInt())

	s := struct {
		IssuerClaim                     *core.Claim `json:"issuerClaim"`
		IssuerClaimNonRevClaimsTreeRoot *big.Int    `json:"issuerClaimNonRevClaimsTreeRoot"`
		IssuerClaimNonRevRevTreeRoot    *big.Int    `json:"issuerClaimNonRevRevTreeRoot"`
		IssuerClaimNonRevRootsTreeRoot  *big.Int    `json:"issuerClaimNonRevRootsTreeRoot"`
		IssuerClaimNonRevState          *big.Int    `json:"issuerClaimNonRevState"`
	}{
		IssuerClaim:                     claim,
		IssuerClaimNonRevClaimsTreeRoot: issuerClaimsTree.Root().BigInt(),
		IssuerClaimNonRevRevTreeRoot:    issuerRevTree.Root().BigInt(),
		IssuerClaimNonRevRootsTreeRoot:  merkletree.HashZero.BigInt(),
		IssuerClaimNonRevState:          issuerState.BigInt(),
	}

	json, _ := json.Marshal(s)
	fmt.Println("Issuer Data:", string(json))
}

func signClaim(kHex string, claim *core.Claim) (*babyjub.Signature, error) {

	hashIndex, hashValue, err := claim.HiHv()
	if err != nil {
		return nil, err
	}

	commonHash, err := poseidon.Hash([]*big.Int{hashIndex, hashValue})
	if err != nil {
		return nil, err
	}

	var privKey babyjub.PrivateKey
	if _, err := hex.Decode(privKey[:], []byte(kHex)); err != nil {
		panic(err)
	}
	bjjSigner := primitive.NewBJJSigner(&privKey)
	sigBytes, err := bjjSigner.Sign(commonHash.Bytes())
	if err != nil {
		return nil, err
	}

	var sig [64]byte
	copy(sig[:], sigBytes)
	return new(babyjub.Signature).Decompress(sig)
}
