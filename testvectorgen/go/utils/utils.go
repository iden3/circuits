package utils

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/iden3/go-iden3-crypto/poseidon"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
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

func AddClaimToTree(tree *merkletree.MerkleTree, claim *core.Claim) (*merkletree.Proof, error) {

	index, value, _ := claim.HiHv()
	err := tree.Add(context.TODO(), index, value)
	if err != nil {
		return nil, err
	}

	proof, _, err := tree.GenerateProof(context.TODO(), index, tree.Root())

	return proof, err
}

func PrintClaim(claimName string, claim *core.Claim) {

	b, err := json.Marshal(claim)
	if err != nil {
		panic(err)
	}

	fmt.Println(claimName, string(b))
}

func GenerateIdentity(ctx context.Context, privKHex string, challenge *big.Int) (*core.ID, *merkletree.MerkleTree, map[string]interface{}) {
	// extract pubKey
	key, X, Y := ExtractPubXY(privKHex)

	// init claims tree
	claimsTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 4)
	ExitOnError(err)

	// create auth claim
	authClaim, err := AuthClaimFromPubKey(X, Y)
	ExitOnError(err)

	// add auth claim to claimsMT
	hi, hv, err := authClaim.HiHv()
	ExitOnError(err)
	err = claimsTree.Add(ctx, hi, hv)
	ExitOnError(err)

	// sign challenge
	decompressedSig, err := SignBBJJ(key, challenge.Bytes())
	ExitOnError(err)

	state, err := core.IdenState(claimsTree.Root().BigInt(), big.NewInt(0), big.NewInt(0))
	ExitOnError(err)
	// create new identity
	identifier, err := core.IdGenesisFromIdenState(core.TypeDefault, state)
	ExitOnError(err)

	// calculate current state
	currentState, err := merkletree.HashElems(claimsTree.Root().BigInt(),
		merkletree.HashZero.BigInt(), merkletree.HashZero.BigInt())
	ExitOnError(err)

	inputs := make(map[string]interface{})
	inputs["id"] = identifier.BigInt().String()
	inputs["BBJAx"] = X.String()
	inputs["BBJAy"] = Y.String()
	inputs["BBJClaimClaimsTreeRoot"] = claimsTree.Root().BigInt().String()
	inputs["challenge"] = challenge.String()
	inputs["challengeSignatureR8x"] = decompressedSig.R8.X.String()
	inputs["challengeSignatureR8y"] = decompressedSig.R8.Y.String()
	inputs["challengeSignatureS"] = decompressedSig.S.String()
	inputs["state"] = currentState.BigInt().String()
	inputs["authClaim"] = ClaimToString(authClaim)
	ExitOnError(err)

	return identifier, claimsTree, inputs
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

func GenerateOnChainSmtWithIdState(identifier *core.ID, state *merkletree.Hash, treeLevels int) *merkletree.MerkleTree {
	ctx := context.Background()
	smt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), treeLevels)
	ExitOnError(err)
	fmt.Println("Identifier", identifier.BigInt().String())
	idHash, err := poseidon.Hash([]*big.Int{identifier.BigInt()})
	fmt.Println("idHash", idHash.String())
	ExitOnError(err)
	err = smt.Add(ctx, idHash, state.BigInt())
	ExitOnError(err)
	return smt
}

func GenerateNullifier(userID *core.ID, salt *big.Int) *big.Int {
	nullifier, err := poseidon.Hash([]*big.Int{userID.BigInt(), salt})
	ExitOnError(err)
	return nullifier
}

func ExtractPubXY(privKHex string) (key *babyjub.PrivateKey, x, y *big.Int) {
	// Extract pubKey
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	pk := k.Public()
	return &k, pk.X, pk.Y
}

func ExitOnError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func AuthClaimFromPubKey(X, Y *big.Int) (*core.Claim, error) {
	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("ca938857241db9451ea329256b9c06e5")
	copy(schemaHash[:], schemaEncodedBytes)

	// NOTE: We take nonce as hash of public key to make it random
	// We don't use random number here because this test vectors will be used for tests
	// and have randomization inside tests is usually a bad idea
	revNonce, err := poseidon.Hash([]*big.Int{X})
	ExitOnError(err)

	return core.NewClaim(schemaHash,
		core.WithIndexDataInts(X, Y),
		core.WithRevocationNonce(revNonce.Uint64()))
}

func SignBBJJ(key *babyjub.PrivateKey, sigInput []byte) (*babyjub.Signature, error) {
	bjjSigner := primitive.NewBJJSigner(key)
	signature, err := bjjSigner.Sign(sigInput)
	ExitOnError(err)

	var sig [64]byte
	copy(sig[:], signature)

	return new(babyjub.Signature).Decompress(sig)
}

func PrintMap(inputs map[string]interface{}) {
	b, err := MarshalIndent(inputs, "", "  ")
	ExitOnError(err)

	fmt.Println(string(b))
}

func PrintSiblings(name string, siblings []*merkletree.Hash) {
	b, err := json.Marshal(siblings)
	if err != nil {
		panic(err)
	}
	fmt.Println(name, string(b))
}

func PadSiblingsToTreeLevels(siblings []*merkletree.Hash, treeLevels int) []*merkletree.Hash {
	s := make([]*merkletree.Hash, treeLevels)
	zero, _ := merkletree.NewHashFromString("0")
	if treeLevels > len(siblings) {
		for i := 0; i < len(siblings); i++ {
			s[i] = siblings[i]
		}
		for i := len(siblings); i < treeLevels; i++ {
			s[i] = zero
		}
	} else {
		for i := 0; i < treeLevels; i++ {
			s[i] = siblings[i]
		}
	}

	return s
}

func ClaimToString(claim *core.Claim) string {
	b, err := json.Marshal(claim)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = Indent(&buf, b, prefix, indent)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// this is a modified method from the json package of stdlib
// it does not print newlines after each item in an array
// this is to make the output more readable and with much less vertical size
func Indent(dst *bytes.Buffer, src []byte, prefix, indent string) error {
	needNewLine := true
	depth := 0
	for _, c := range src {

		// Add spacing around real punctuation.
		switch c {
		case '{':
			dst.WriteByte(c)
			depth++
			newline(dst, prefix, indent, depth)

		case '[':
			dst.WriteByte(c)
			needNewLine = false

		case ',':
			dst.WriteByte(c)
			if needNewLine {
				newline(dst, prefix, indent, depth)
			}

		case ':':
			dst.WriteByte(c)
			dst.WriteByte(' ')

		case '}':
			depth--
			newline(dst, prefix, indent, depth)
			dst.WriteByte(c)

		case ']':
			needNewLine = true
			dst.WriteByte(c)

		default:
			dst.WriteByte(c)
		}
	}
	return nil
}

func newline(dst *bytes.Buffer, prefix, indent string, depth int) {
	dst.WriteByte('\n')
	dst.WriteString(prefix)
	for i := 0; i < depth; i++ {
		dst.WriteString(indent)
	}
}
