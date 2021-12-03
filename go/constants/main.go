package main

import (
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"math/big"
)

func main() {
	zeroes := [6]*big.Int{}
	for i := range zeroes {
		zeroes[i] = new(big.Int)
	}
	hZeroes, err := poseidon.Hash(zeroes[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("Poseidon[0, 0, 0, 0, 0, 0] = %v\n", hZeroes)

	ffZeroes := [6]*big.Int{}
	for i := range ffZeroes {
		ffZeroes[i] = new(big.Int)
	}
	ffZeroes[0].SetUint64(0xffff_ffff)
	hffZeroes, err := poseidon.Hash(ffZeroes[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("Poseidon[0xffff_ffff, 0, 0, 0, 0, 0] = %v\n", hffZeroes)

	id, _ := core.IDFromString("117twYCgGzxHUtMsAfjM3muCrypTXcu6oc7cSsuGHM")

	schemaHash := core.SchemaHash{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	claim, err := core.NewClaim(
		schemaHash,
		core.WithID(id, core.IDPositionIndex),
		//nolint:gosec //reason: no need for security
		core.WithRevocationNonce(123),
	)

	entry := claim.TreeEntry()
	fmt.Println("Demo Claim:")
	fmt.Printf("%v\n", entry.Data[0].BigInt())
	fmt.Printf("%v\n", entry.Data[1].BigInt())
	fmt.Printf("%v\n", entry.Data[2].BigInt())
	fmt.Printf("%v\n", entry.Data[3].BigInt())
	fmt.Printf("%v\n", entry.Data[4].BigInt())
	fmt.Printf("%v\n", entry.Data[5].BigInt())
	fmt.Printf("%v\n", entry.Data[6].BigInt())
	fmt.Printf("%v\n", entry.Data[7].BigInt())
}
