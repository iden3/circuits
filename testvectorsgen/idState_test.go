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
	cryptoUtils "github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"
)

const nLevels = 3

func pruneBuffer(buf *[32]byte) *[32]byte {
	buf[0] = buf[0] & 0xF8
	buf[31] = buf[31] & 0x7F
	buf[31] = buf[31] | 0x40
	return buf
}

func skToBigInt(k *babyjub.PrivateKey) *big.Int {
	sBuf := babyjub.Blake512(k[:])
	sBuf32 := [32]byte{}
	copy(sBuf32[:], sBuf[:32])
	pruneBuffer(&sBuf32)
	s := new(big.Int)
	cryptoUtils.SetBigIntFromLEBytes(s, sBuf32[:])
	s.Rsh(s, 3)
	return s
}

func TestIdStateInputs(t *testing.T) {
	fmt.Println("\n-------\nIdState test vectors:")

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

	clt, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), 3)
	assert.Nil(t, err)
	rot, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), 3)
	assert.Nil(t, err)

	id, err := genesis.CalculateIdGenesisMT(clt, rot, claimKOp, []merkletree.Entrier{})
	assert.Nil(t, err)
	fmt.Println("id", id)

	// get claimproof
	hi, err := claimKOp.Entry().HIndex()
	assert.Nil(t, err)
	fmt.Println("claim hi", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(hi)))
	proof, err := clt.GenerateProof(hi, nil)
	assert.Nil(t, err)
	fmt.Println(proof)
	fmt.Println(proof.Bytes())
	fmt.Println(proof.Siblings)
	for _, s := range proof.Siblings {
		fmt.Println("s", s)
	}
	fmt.Println("claimsTreeRoot", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(clt.RootKey()))) // internally SwapsEndianness of the bytes
	// mtp := ProofToMTP(proof)
	// fmt.Println(mtp)

	fmt.Println("\nEnd of IdState test vectors\n-----")
}

// func ProofToMTP(p *merkletree.Proof) []byte {
//         var siblings [][]byte
//
//         bsLen := merkletree.ProofFlagsLen + len(p.NotEmpties) + merkletree.ElemBytesLen*len(p.Siblings)
//         fmt.Println(bsLen)
//         // if p.NodeAux != nil {
//         //         bsLen += 2 * merkletree.ElemBytesLen
//         // }
//         // bs := make([]byte, bsLen)
//         //
//         // for i, k := range p.Siblings {
//         //
//         // }
//
//         siblings = append(siblings, []byte{0}) // circom leaf protection
//         return []byte{}
// }
