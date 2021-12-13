package main

import (
	"encoding/hex"
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

func exitOnError(err error) {
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

func SignatureInputs(key *babyjub.PrivateKey, sigInput []byte) (*babyjub.Signature, error) {
	bjjSigner := primitive.NewBJJSigner(key)
	signature, err := bjjSigner.Sign(sigInput)
	exitOnError(err)

	var sig [64]byte
	copy(sig[:], signature)

	fmt.Println("Sig")
	fmt.Println(hex.EncodeToString(sig[:]))

	return new(babyjub.Signature).Decompress(sig)
}
