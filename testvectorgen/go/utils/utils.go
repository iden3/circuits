package utils

import (
	"encoding/hex"
	json "encoding/json"
	"fmt"
	"math/big"
	"os"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"test/crypto/primitive"
)

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

func PrintMap(inputs map[string]string) {
	json, err := json.Marshal(inputs)
	ExitOnError(err)

	fmt.Println(string(json))
}

func PrintSiblings(name string, siblings []*merkletree.Hash) {
	json, err := json.Marshal(siblings)
	if err != nil {
		panic(err)
	}
	fmt.Println(name, string(json))
}

func SiblingsToString(siblings []*merkletree.Hash, treeLevels int) string {
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

	res, err := json.Marshal(s)
	ExitOnError(err)
	return string(res)
}

func ClaimToString(claim *core.Claim) string {
	json, err := json.Marshal(claim)
	if err != nil {
		panic(err)
	}
	return string(json)
}
