package main

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
)

func TestPoseidon(t *testing.T) {
	fmt.Println("\n-------\nPoseidon test vectors:")
	z := big.NewInt(0)
	r, err := poseidon.Hash([]*big.Int{z, z, z, z, z, z})
	assert.Nil(t, err)
	fmt.Println("PoseidonHash [0]", r)

	r, err = poseidon.Hash([]*big.Int{z, z, z, z})
	assert.Nil(t, err)
	fmt.Println("Hash [0]", r)

	o := big.NewInt(1)
	r, err = poseidon.Hash([]*big.Int{o, z, z, z, z, z})
	assert.Nil(t, err)
	fmt.Println("PoseidonHash [1, 0]", r)

	o = big.NewInt(2)
	r, err = poseidon.Hash([]*big.Int{o, z, z, z, z, z})
	assert.Nil(t, err)
	fmt.Println("PoseidonHash [2, 0]", r)

	r, err = poseidon.Hash([]*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(4), z, z, z})
	assert.Nil(t, err)
	fmt.Println("PoseidonHash [2, 3, 4]", r)
	fmt.Println("\nEnd of Poseidon test vectors\n-----")
}
