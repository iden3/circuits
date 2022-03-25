package utils

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
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
	err := tree.AddEntry(context.TODO(), &entry)
	if err != nil {
		return nil, err
	}

	proof, _, err := tree.GenerateProof(context.TODO(), index.BigInt(), tree.Root())

	return proof, err
}

func PrintClaim(claimName string, claim *core.Claim) {

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

	fmt.Println(claimName, string(json))
}

func GenerateIdentity(ctx context.Context, privKHex string, challenge *big.Int) (*core.ID, *merkletree.MerkleTree, map[string]string) {
	// extract pubKey
	key, X, Y := ExtractPubXY(privKHex)

	// init claims tree
	claimsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 4)
	ExitOnError(err)

	// create auth claim
	authClaim, err := AuthClaimFromPubKey(X, Y)
	ExitOnError(err)

	// add auth claim to claimsMT
	entry := authClaim.TreeEntry()
	hi, hv, err := entry.HiHv()
	ExitOnError(err)
	claimsTree.Add(ctx, hi.BigInt(), hv.BigInt())

	// sign challenge
	decompressedSig, err := SignBBJJ(key, challenge.Bytes())
	ExitOnError(err)

	// create new identity
	identifier, err := core.CalculateGenesisID(claimsTree.Root())
	ExitOnError(err)

	// calculate current state
	currentState, err := merkletree.HashElems(claimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(), merkletree.HashZero.BigInt())
	ExitOnError(err)

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
	inputs["authClaim"], _ = ClaimToString(authClaim)
	ExitOnError(err)

	return identifier, claimsTree, inputs
}

func GenerateIdentity2(ctx context.Context, privKHex string, challenge *big.Int) (*core.ID, *merkletree.MerkleTree, *core.Claim, *babyjub.PrivateKey, error) {

	// extract pubKey
	var privKey babyjub.PrivateKey

	if _, err := hex.Decode(privKey[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	X := privKey.Public().X
	Y := privKey.Public().Y

	// init claims tree
	claimsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// create auth claim
	authClaim, err := AuthClaimFromPubKey(X, Y)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// add auth claim to claimsMT
	entry := authClaim.TreeEntry()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	hi, hv, err := entry.HiHv()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	err = claimsTree.Add(ctx, hi.BigInt(), hv.BigInt())
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// create new identity
	identifier, err := core.CalculateGenesisID(claimsTree.Root())
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return identifier, claimsTree, authClaim, &privKey, nil
}

func FormatInput(input interface{}) string {
	var value string
	switch v := input.(type) {
	case *merkletree.Hash:
		value = v.BigInt().String()
	case *core.ID:
		value = v.BigInt().String()
	default:
		ExitOnError(errors.New("Unknown input type. Can't format to string."))
	}
	return value
}

func CalcIdentityStateFromRoots(claimsTree *merkletree.MerkleTree, optTrees ...*merkletree.MerkleTree) (*merkletree.Hash, error) {
	revTreeRoot := merkletree.HashZero.BigInt()
	rootsTreeRoot := merkletree.HashZero.BigInt()
	if len(optTrees) > 0 {
		revTreeRoot = optTrees[0].Root().BigInt()
	}
	if len(optTrees) > 1 {
		rootsTreeRoot = optTrees[1].Root().BigInt()
	}
	state, err := merkletree.HashElems(
		claimsTree.Root().BigInt(),
		revTreeRoot,
		rootsTreeRoot)
	return state, err
}

func GenerateRelayWithIdenStateClaim(relayPrivKey string, identifier *core.ID, idenState *merkletree.Hash) (*core.Claim, *merkletree.Hash, *merkletree.Hash, *merkletree.Proof) {
	ctx := context.Background()
	_, relayClaimsTree, _ := GenerateIdentity(ctx, relayPrivKey, big.NewInt(0))

	valueSlotA, _ := core.NewDataSlotFromInt(idenState.BigInt())
	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("e22dd9c0f7aef15788c130d4d86c7156")
	copy(schemaHash[:], schemaEncodedBytes)
	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(*identifier),
		core.WithValueData(valueSlotA, core.DataSlot{}),
	)
	ExitOnError(err)

	proofIdentityIsRelayed, err := AddClaimToTree(relayClaimsTree, claim)
	ExitOnError(err)
	relayState, err := CalcIdentityStateFromRoots(relayClaimsTree)
	ExitOnError(err)

	return claim, relayState, relayClaimsTree.Root(), proofIdentityIsRelayed
}
