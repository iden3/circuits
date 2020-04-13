package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	common3 "github.com/iden3/go-iden3-core/common"
	"github.com/iden3/go-iden3-core/core/claims"
	"github.com/iden3/go-iden3-core/core/genesis"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-core/merkletree"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/assert"
)

func TestCredential(t *testing.T) {
	fmt.Println("\n-------\nCredential test vectors:")

	nLevels := 3

	privKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	// Create new claim
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	fmt.Println("sk", skToBigInt(&k))
	fmt.Println("sk", new(big.Int).SetBytes(k[:]))
	fmt.Println("sk", new(big.Int).SetBytes(common3.SwapEndianness(k[:])))
	pk := k.Public()
	fmt.Println("sign", babyjub.PointCoordSign(pk.X))
	fmt.Println("y", pk.Y)

	claimKOp := claims.NewClaimAuthorizeKSignBabyJub(pk)

	clt, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)
	rot, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)

	id, err := genesis.CalculateIdGenesisMT(clt, rot, claimKOp, []merkletree.Entrier{})
	assert.Nil(t, err)
	fmt.Println("id", new(big.Int).SetBytes(id.Bytes()))
	fmt.Println("id", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))

	// get claimproof
	hi, err := claimKOp.Entry().HIndex()
	assert.Nil(t, err)
	fmt.Println("claim hi", new(big.Int).SetBytes(common3.SwapEndianness(hi[:])))
	fmt.Println("claim hi", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(hi)))
	oProof, err := clt.GenerateProof(hi, nil)
	assert.Nil(t, err)
	fmt.Println(oProof)
	fmt.Println(oProof.Bytes())
	fmt.Println(oProof.Siblings)
	for _, s := range oProof.Siblings {
		fmt.Println("s", s)
	}
	fmt.Println("oClaimsTreeRoot", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Println("oClaimsTreeRoot", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(clt.RootKey()))) // internally SwapsEndianness of the bytes
	fmt.Println("oRootsTreeRoot", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(rot.RootKey())))
	// oMtp := ProofToMTP(oProof)
	// fmt.Println(oMtp)

	// create Issuer tree
	issuerTree, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), 3)
	assert.Nil(t, err)
	// build ClaimBasic about Id
	var indexSlot [claims.IndexSlotLen]byte
	var valueSlot [claims.ValueSlotLen]byte
	// copy(indexSlot[(152/8):], common3.SwapEndianness(id.Bytes()))
	copy(indexSlot[(152/8):], id.Bytes())
	claimAboutId := claims.NewClaimBasic(indexSlot, valueSlot)
	hiClaimAboutId, _ := claimAboutId.Entry().HIndex()
	fmt.Println("ClaimAboutId hi", new(big.Int).SetBytes(common3.SwapEndianness(hiClaimAboutId[:])))
	// hvClaimAboutId, _ := claimAboutId.Entry().HValue()
	// add ClaimAboutId to issuerTree
	err = issuerTree.AddClaim(claimAboutId)
	assert.Nil(t, err)
	// proof, err := clt.GenerateProof(hiClaimAboutId, nil)
	// assert.Nil(t, err)

	fmt.Println("--- copy & paste into idState.test.js ---")
	fmt.Printf(`issuerRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(issuerTree.RootKey().Bytes())))
	fmt.Printf(`mtp: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`id: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))
	fmt.Printf(`// id: "%s",`+"\n", new(big.Int).SetBytes(id.Bytes()))

	fmt.Printf(`oUserPrivateKey: "%s",`+"\n", skToBigInt(&k))
	fmt.Printf(`oPbkAx: "%s",`+"\n", pk.X)
	fmt.Printf(`oPbkAy: "%s",`+"\n", pk.Y)
	fmt.Printf(`oMtp: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`oClaimsTreeRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Printf(`oRevTreeRoot: "0",` + "\n") // TMP
	fmt.Printf(`oRootsTreeRoot: "%s"`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(rot.RootKey().Bytes())))
	fmt.Println("--- end of copy & paste to idState.test.js ---")

	fmt.Println("\nEnd of Credential test vectors\n-----")
}
