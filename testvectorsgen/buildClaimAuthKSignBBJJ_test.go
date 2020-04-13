package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	common3 "github.com/iden3/go-iden3-core/common"
	"github.com/iden3/go-iden3-core/core/claims"
	"github.com/iden3/go-iden3-core/merkletree"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

func TestBuildClaimAuthKSignBabyJubJub(t *testing.T) {
	fmt.Println("\n-------\nBuildClaimAuthKSignBabyJubJub test vectors:")
	privKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	// Create new claim
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	pk := k.Public()
	fmt.Println("sign", babyjub.PointCoordSign(pk.X))
	fmt.Println("x", pk.X)
	fmt.Println("y", pk.Y)

	swapYBytes := common3.SwapEndianness(pk.Y.Bytes())
	swapY := new(big.Int).SetBytes(swapYBytes)
	fmt.Println("swappedY", swapY)
	fmt.Println("cmp", pk.Compress())

	c0 := claims.NewClaimAuthorizeKSignBabyJub(pk)
	fmt.Println(c0.Entry().Bytes())
	fmt.Println("e0", c0.Entry().Data[0][:])
	fmt.Println("swap(e0)", common3.SwapEndianness(c0.Entry().Data[0][:]))
	fmt.Println("swap(e0)", new(big.Int).SetBytes(common3.SwapEndianness(c0.Entry().Data[0][:])))
	fmt.Println("e0", new(big.Int).SetBytes(c0.Entry().Data[0][:]))
	fmt.Println("e0", new(big.Int).SetBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}))
	fmt.Println("swap(e1)", new(big.Int).SetBytes(common3.SwapEndianness(c0.Entry().Data[1][:])))
	fmt.Println("e1", new(big.Int).SetBytes(c0.Entry().Data[1][:]))
	fmt.Println("swap(e2)", new(big.Int).SetBytes(common3.SwapEndianness(c0.Entry().Data[2][:])))
	fmt.Println("e2", new(big.Int).SetBytes(c0.Entry().Data[2][:]))
	fmt.Println("e3", new(big.Int).SetBytes(c0.Entry().Data[3][:]))

	hi, _ := c0.Entry().HIndex()
	hv, _ := c0.Entry().HValue()
	fmt.Println("hi", hi.Hex())
	fmt.Println("hv", hv.Hex())
	// e := (*merkletree.ElemBytes)(hv)
	fmt.Println(c0.Entry().Index())
	fmt.Println("hi string", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(hi)))
	fmt.Println("hi bytes swapp", new(big.Int).SetBytes(common3.SwapEndianness(hi[:])))
	fmt.Println("hi bytes noswp", new(big.Int).SetBytes(hi[:]))

	fmt.Println("hv string", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(hv)))

	fmt.Println("--- copy & paste into claimAuthKSignBabyJubJub.test.js ---")
	fmt.Printf(`ax: "%s",`+"\n", pk.X)
	fmt.Printf(`ay: "%s"`+"\n", pk.Y)
	fmt.Println("--- end of copy & paste to claimAuthKSignBabyJubJub.test.js ---")

	fmt.Println("Expected outputs:")
	fmt.Println("hi:", new(big.Int).SetBytes(common3.SwapEndianness(hi[:])))
	fmt.Println("hv:", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(hv)))

	// c0.Metadata().RevNonce = 5678
	// assert.True(t, merkletree.CheckEntryInField(*c0.Entry()))
	// e := c0.Entry()
	// c1 := claims.NewClaimAuthorizeKSignBabyJubFromEntry(e)
	// c2, err := claims.NewClaimFromEntry(e)
	// assert.Nil(t, err)
	// assert.Equal(t, c0, c1)
	// assert.Equal(t, c0.Metadata(), c1.Metadata())
	// assert.Equal(t, c0, c2)
	// assert.True(t, merkletree.CheckEntryInField(*e))
	fmt.Println("\nEnd of BuildClaimAuthKSignBabyJub test vectors\n-----")
}
