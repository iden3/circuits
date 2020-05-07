package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-core/core"
	"github.com/iden3/go-iden3-core/core/claims"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

func main() {
	zeroes := [6]*big.Int{}
	for i := range zeroes {
		zeroes[i] = new(big.Int)
	}
	hZeroes, err := poseidon.PoseidonHash(zeroes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Poseidon[0, 0, 0, 0, 0, 0] = %v\n", hZeroes)

	ffZeroes := [6]*big.Int{}
	for i := range ffZeroes {
		ffZeroes[i] = new(big.Int)
	}
	ffZeroes[0].SetUint64(0xffff_ffff)
	hffZeroes, err := poseidon.PoseidonHash(ffZeroes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Poseidon[0xffff_ffff, 0, 0, 0, 0, 0] = %v\n", hffZeroes)

	id := core.NewID(core.TypeBJP0, [27]byte{})
	indexBytes, valueBytes := [claims.IndexSubjectSlotLen]byte{}, [claims.ValueSlotLen]byte{}
	claim := claims.NewClaimOtherIden(&id, indexBytes, valueBytes)
	entry := claim.Entry()
	fmt.Printf("Demo ClaimOtherIden i0 = %v\n", entry.Data[0].BigInt())
	fmt.Printf("%v\n", hex.EncodeToString(entry.Data[0][:]))
}
