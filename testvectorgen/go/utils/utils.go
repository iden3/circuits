package utils

import (
	"encoding/hex"
	json "encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"math/big"
	"os"
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
	schemaEncodedBytes, _ := hex.DecodeString("7c0844a075a9ddc7fcbdfb4f88acd9bc")
	copy(schemaHash[:], schemaEncodedBytes)

	return core.NewClaim(schemaHash,
		core.WithIndexDataInts(X, Y),
		core.WithRevocationNonce(uint64(0)))
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

func ClaimToString(claim *core.Claim) (string, error) {
	slots := make([]*big.Int, 0)
	entry := claim.TreeEntry()
	indexes := entry.Index()
	values := entry.Value()
	for _, index := range indexes {
		slots = append(slots, index.BigInt())
	}
	for _, value := range values {
		slots = append(slots, value.BigInt())
	}
	json, err := json.Marshal(slots)
	return string(json), err
}
