package main
//
//import (
//	"encoding/hex"
//	"fmt"
//	"math/big"
//	"testing"
//
//	common3 "github.com/iden3/go-iden3-core/common"
//	"github.com/iden3/go-iden3-core/core/claims"
//	"github.com/iden3/go-iden3-crypto/babyjub"
//)
//
//func TestBuildClaimKeyBabyJubJub(t *testing.T) {
//	fmt.Println("\n-------\nBuildClaimKeyBabyJubJub test vectors:")
//	privKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
//	// Create new claim
//	var k babyjub.PrivateKey
//	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
//		panic(err)
//	}
//	pk := k.Public()
//	fmt.Println("x", pk.X)
//	fmt.Println("y", pk.Y)
//
//	c0 := claims.NewClaimKeyBabyJub(pk, 1)
//	fmt.Println(c0.Entry().Bytes())
//
//	hi, _ := c0.Entry().HIndex()
//	hv, _ := c0.Entry().HValue()
//	fmt.Println(c0.Entry().Index())
//
//	fmt.Println("hi string", hi.BigInt())
//	fmt.Println("hi bytes swapp", new(big.Int).SetBytes(common3.SwapEndianness(hi[:])))
//	fmt.Println("hi bytes noswp", new(big.Int).SetBytes(hi[:]))
//
//	fmt.Println("hv string", hv.BigInt())
//
//	fmt.Println("--- copy & paste into claimKeyBabyJubJub.test.js ---")
//	fmt.Printf(`ax: "%s",`+"\n", pk.X)
//	fmt.Printf(`ay: "%s"`+"\n", pk.Y)
//	fmt.Println("--- end of copy & paste to claimKeyBabyJubJub.test.js ---")
//
//	fmt.Println("Expected outputs:")
//	fmt.Println("hi:", hi.BigInt())
//	fmt.Println("hv:", hv.BigInt())
//
//	fmt.Println("\nEnd of BuildClaimKeyBabyJub test vectors\n-----")
//}
