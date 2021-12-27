package utils

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"math"
	"math/big"
	"test/crypto/primitive"
)

func PrintCurrentState(claimsTree *merkletree.MerkleTree) {
	// calculate current state
	currentState, err := merkletree.HashElems(claimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(), merkletree.HashZero.BigInt())
	ExitOnError(err)

	fmt.Println("Current state Hex:", currentState)
	fmt.Println("Current state BigInt:", currentState.BigInt())
}

func SignatureInputs(key *babyjub.PrivateKey, sigInput []byte) (*babyjub.Signature, error) {
	bjjSigner := primitive.NewBJJSigner(key)
	signature, err := bjjSigner.Sign(sigInput)
	ExitOnError(err)

	var sig [64]byte
	copy(sig[:], signature)

	fmt.Println("Sig")
	fmt.Println(hex.EncodeToString(sig[:]))

	return new(babyjub.Signature).Decompress(sig)
}

func GenerateInputsIdOwnershipBySignature(claimsTree *merkletree.MerkleTree, privKHex string) (*core.ID, map[string]string) {

	inputs := make(map[string]string)

	// Extract pubKey
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	pk := k.Public()
	inputs["BBJAx"] = pk.X.String()
	inputs["BBJAy"] = pk.Y.String()

	identifier := generateIDInputs(pk, claimsTree, inputs)

	inputs["BBJClaimClaimsTreeRoot"] = claimsTree.Root().BigInt().String()

	// Test signature
	challenge := new(big.Int).SetUint64(math.MaxUint64)
	inputs["challenge"] = challenge.String()

	signatureInputs(&k, challenge.Bytes(), inputs)

	return identifier, inputs
}

func signatureInputs(key *babyjub.PrivateKey, sigInput []byte, inputs map[string]string) {
	bjjSigner := primitive.NewBJJSigner(key)
	signature, err := bjjSigner.Sign(sigInput)
	ExitOnError(err)

	var sig [64]byte
	copy(sig[:], signature)
	var decompressedSig *babyjub.Signature
	decompressedSig, err = new(babyjub.Signature).Decompress(sig)
	ExitOnError(err)

	inputs["challengeSignatureR8x"] = decompressedSig.R8.X.String()
	inputs["challengeSignatureR8y"] = decompressedSig.R8.Y.String()
	inputs["challengeSignatureS"] = decompressedSig.S.String()

	//inputs["BBJClaimRevTreeRoot"] = merkletree.HashZero
	//inputs["BBJClaimRootsTreeRoot"] = merkletree.HashZero

}

func generateIDInputs(pk *babyjub.PublicKey, claimsTree *merkletree.MerkleTree, inputs map[string]string) *core.ID {

	// Create auth claim
	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("7c0844a075a9ddc7fcbdfb4f88acd9bc")
	copy(schemaHash[:], schemaEncodedBytes)

	authClaim, err := core.NewClaim(schemaHash,
		core.WithIndexDataInts(pk.X, pk.Y),
		//nolint:gosec //reason: no need for security
		core.WithRevocationNonce(uint64(0)))
	ExitOnError(err)

	entry := authClaim.TreeEntry()
	claimsTree.AddEntry(context.Background(), &entry) // add claim to the MT

	// generate id
	identifier, err := core.CalculateGenesisID(claimsTree.Root())
	ExitOnError(err)

	fmt.Println("Identifier:", identifier)
	inputs["id"] = identifier.BigInt().String()

	authEntry := authClaim.TreeEntry()
	index, err := authEntry.HIndex()
	ExitOnError(err)

	//MTP
	proof, _, err := claimsTree.GenerateProof(context.Background(), index.BigInt(), claimsTree.Root())
	ExitOnError(err)

	fmt.Printf("%+v\n", proof)
	fmt.Printf("%+v\n", proof.AllSiblings())

	return identifier
}

func GenerateClaimAndInputs(tree *merkletree.MerkleTree, claim *core.Claim) map[string]string {

	cIn := ""
	inputs := make(map[string]string)

	entry := claim.TreeEntry()
	indexes := entry.Index()
	values := entry.Value()
	for _, index := range indexes {
		cIn += index.BigInt().String() + ","
	}
	for _, value := range values {
		cIn += value.BigInt().String() + ","
	}

	inputs["claim"] = cIn

	proof, _ := AddClaimToTree(tree, claim)

	fmt.Println("-------claim proof--------")
	fmt.Println("Siblings:")
	siblingsStr := ""
	siblings := proof.AllSiblings()

	for _, sibling := range siblings {
		siblingsStr += sibling.BigInt().String() + ","
	}
	inputs["claimIssuanceMtp"] = siblingsStr
	fmt.Println("-------end--------")

	return inputs

}

func AddClaimToTree(tree *merkletree.MerkleTree, claim *core.Claim) (*merkletree.Proof, error) {

	entry := claim.TreeEntry()
	index, _ := entry.HIndex()
	tree.AddEntry(context.TODO(), &entry)

	proof, _, err := tree.GenerateProof(context.TODO(), index.BigInt(), tree.Root())

	return proof, err
}

func PrintClaim(claim *core.Claim) {

	cIn := make([]string, 0)
	entry := claim.TreeEntry()
	indexes := entry.Index()
	values := entry.Value()
	for _, index := range indexes {
		cIn = append(cIn, index.BigInt().String())
	}
	for _, value := range values {
		cIn = append(cIn, value.BigInt().String())
	}

	json, err := json.Marshal(cIn)
	if err != nil {
		panic(err)
	}

	fmt.Println("\"claim\":", string(json))

}
