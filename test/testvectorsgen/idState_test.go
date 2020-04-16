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
	"github.com/iden3/go-iden3-crypto/poseidon"
	cryptoUtils "github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"
)

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

	claimKOp := claims.NewClaimKeyBabyJub(pk, 1)

	clt, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)
	rot, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)

	id, err := genesis.CalculateIdGenesisMT(clt, rot, claimKOp, []merkletree.Entrier{})
	assert.Nil(t, err)
	fmt.Println("id", id)
	fmt.Println("id", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))

	// Example of calculating the RootsTreeRoot directly with hashes
	// it needs 3 hashes
	hiInput := [poseidon.T]*big.Int{
		new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	}
	hiL, err := poseidon.PoseidonHash(hiInput)
	hvInput := [poseidon.T]*big.Int{
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	}
	hvL, err := poseidon.PoseidonHash(hvInput)
	tmpInput := [poseidon.T]*big.Int{
		hiL,
		hvL,
		big.NewInt(1),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	}
	calculatedRoT, err := poseidon.PoseidonHash(tmpInput)
	assert.Nil(t, err)
	fmt.Println("\ntmp", calculatedRoT)
	fmt.Println("exp", new(big.Int).SetBytes(common3.SwapEndianness(rot.RootKey().Bytes())))
	assert.Equal(t, calculatedRoT, new(big.Int).SetBytes(common3.SwapEndianness(rot.RootKey().Bytes())))
	assert.Equal(t, "4993494596562389383889749727008725160160552507022773815483402975297010560970", new(big.Int).SetBytes(common3.SwapEndianness(rot.RootKey().Bytes())).String())

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
	fmt.Println("claimsTreeRoot", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Println("claimsTreeRoot", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(clt.RootKey()))) // internally SwapsEndianness of the bytes
	fmt.Println("rootsTreeRoot", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(rot.RootKey())))
	// mtp := ProofToMTP(proof)
	// fmt.Println(mtp)

	// newIdState
	newIdState := new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes()))

	// nullifier
	// var zero32 [32]byte
	// oldIdState := zero32[:]
	// bi := [poseidon.T]*big.Int{
	//         skToBigInt(&k),
	//         new(big.Int).SetBytes(oldIdState),
	//         newIdState,
	//         big.NewInt(0),
	//         big.NewInt(0),
	//         big.NewInt(0),
	// }
	// nullifier, err := poseidon.PoseidonHash(bi)
	// assert.Nil(t, err)

	fmt.Println("--- copy & paste into idState.test.js ---")
	fmt.Printf(`id: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))
	// fmt.Printf(`nullifier: "%s",`+"\n", nullifier)
	fmt.Printf(`oldIdState: "%s",`+"\n", "0")
	fmt.Printf(`userPrivateKey: "%s",`+"\n", skToBigInt(&k))
	fmt.Printf(`siblings: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`claimsTreeRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Println("// revTreeRoot & rootsTreeRoot are not used in this implementation, as uses idOwnershipGenesis.circom")
	fmt.Printf(`// revTreeRoot: "0",` + "\n") // TMP
	fmt.Printf(`// rootsTreeRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(rot.RootKey().Bytes())))
	fmt.Printf(`newIdState: "%s"`+"\n", newIdState) // TMP
	fmt.Println("--- end of copy & paste to idState.test.js ---")

	fmt.Println("\n--- copy & paste into idOwnership.test.js ---")
	fmt.Printf(`id: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))
	fmt.Printf(`userPrivateKey: "%s",`+"\n", skToBigInt(&k))
	fmt.Printf(`siblings: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`claimsTreeRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Printf(`revTreeRoot: "0",` + "\n") // TMP
	fmt.Printf(`rootsTreeRoot: "%s"`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(rot.RootKey().Bytes())))
	fmt.Println("--- end of copy & paste to idOwnership.test.js ---")
	fmt.Println("\n--- copy & paste into idOwnershipGenesis.test.js ---")
	fmt.Printf(`id: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))
	fmt.Printf(`userPrivateKey: "%s",`+"\n", skToBigInt(&k))
	fmt.Printf(`siblings: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`claimsTreeRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Println("--- end of copy & paste to idOwnershipGenesis.test.js ---")

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
