package main

import (
	"fmt"
	"math/big"
	"testing"

	common3 "github.com/iden3/go-iden3-core/common"
	"github.com/iden3/go-iden3-core/core/claims"
	"github.com/iden3/go-iden3-core/merkletree"
	"github.com/stretchr/testify/assert"
)

func TestBuildClaimBasicAboutId(t *testing.T) {
	fmt.Println("\n-------\nBuildClaimBasicAboutId test vectors:")

	id, ok := new(big.Int).SetString("42480995223634099390927232964573436282320794921974209609166261920409845760", 10)
	assert.True(t, ok)
	fmt.Println("id: swap(id)", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))

	var indexSlot [claims.IndexSlotLen]byte
	var valueSlot [claims.ValueSlotLen]byte
	copy(indexSlot[(152/8):], id.Bytes())
	c0 := claims.NewClaimBasic(indexSlot, valueSlot)
	fmt.Println(c0.Entry().Bytes())

	fmt.Println(id.Bytes())
	fmt.Println(c0.Entry().Data[0])
	fmt.Println(c0.Entry().Data[1])
	fmt.Println(c0.Entry().Data[2])
	fmt.Println(c0.Entry().Data[3])

	fmt.Println("swap(e0)", new(big.Int).SetBytes(common3.SwapEndianness(c0.Entry().Data[0][:])))
	fmt.Println("swap(e1)", new(big.Int).SetBytes(common3.SwapEndianness(c0.Entry().Data[1][:])))

	hi, _ := c0.Entry().HIndex()
	hv, _ := c0.Entry().HValue()

	fmt.Println("hi string", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(hi)))
	fmt.Println("hi bytes swapp", new(big.Int).SetBytes(common3.SwapEndianness(hi[:])))

	fmt.Println("hv string", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(hv)))

	fmt.Println("\nEnd of BuildClaimAuthKSignBabyJub test vectors\n-----")
}
