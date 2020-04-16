package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"testing"

	common3 "github.com/iden3/go-iden3-core/common"
	"github.com/iden3/go-iden3-core/core/claims"
	"github.com/iden3/go-iden3-core/core/genesis"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-core/merkletree"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/assert"
)

func TestCredentialOnly1ClaimInTree(t *testing.T) {
	fmt.Println("\n-------\nCredential (simple tree) test vectors:")

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
	fmt.Println("len siblings", len(oProof.Siblings))
	for _, s := range oProof.Siblings {
		fmt.Println("s", s)
	}
	fmt.Println("oClaimsTreeRoot", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Println("oClaimsTreeRoot", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(clt.RootKey()))) // internally SwapsEndianness of the bytes
	fmt.Println("oRootsTreeRoot", merkletree.ElemBytesToBigInt(*(*merkletree.ElemBytes)(rot.RootKey())))

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

	fmt.Println("--- copy & paste into credential.test.js ---")
	fmt.Printf(`issuerRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(issuerTree.RootKey().Bytes())))
	fmt.Printf(`siblings: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`id: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))
	fmt.Printf(`// id: "%s",`+"\n", new(big.Int).SetBytes(id.Bytes()))

	fmt.Printf(`oUserPrivateKey: "%s",`+"\n", skToBigInt(&k))
	fmt.Printf(`oSiblings: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`oClaimsTreeRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Printf(`// oRevTreeRoot: "0",` + "\n") // TMP
	fmt.Printf(`// oRootsTreeRoot: "%s"`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(rot.RootKey().Bytes())))
	fmt.Println("--- end of copy & paste to credential.test.js ---")

	fmt.Println("\nEnd of Credential (simple tree) test vectors\n-----")
}

func TestCredentialMultipleClaimsInTree1(t *testing.T) {
	fmt.Println("\n-------\nCredential multiple claims in tree test vectors 1:")

	nLevels := 3
	issuerNumLevels := 10

	privKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	// Create new claim
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	pk := k.Public()

	claimKOp := claims.NewClaimKeyBabyJub(pk, 1)

	clt, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)
	rot, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)

	id, err := genesis.CalculateIdGenesisMT(clt, rot, claimKOp, []merkletree.Entrier{})
	assert.Nil(t, err)

	// create Issuer tree
	issuerTree, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), issuerNumLevels)
	assert.Nil(t, err)
	// build ClaimBasic about Id
	var indexSlot [claims.IndexSlotLen]byte
	var valueSlot [claims.ValueSlotLen]byte
	// copy(indexSlot[(152/8):], common3.SwapEndianness(id.Bytes()))
	copy(indexSlot[(152/8):], id.Bytes())
	claimAboutId := claims.NewClaimBasic(indexSlot, valueSlot)
	hiClaimAboutId, _ := claimAboutId.Entry().HIndex()
	// fmt.Println("ClaimAboutId hi", new(big.Int).SetBytes(common3.SwapEndianness(hiClaimAboutId[:])))
	// hvClaimAboutId, _ := claimAboutId.Entry().HValue()

	// add ClaimAboutId to issuerTree
	err = issuerTree.AddClaim(claimAboutId)
	assert.Nil(t, err)

	// add padding claims
	fmt.Println(issuerTree.RootKey())
	issuerTree, err = addExtraClaims(issuerTree, 2)
	assert.Nil(t, err)
	fmt.Println(issuerTree.RootKey())

	// generate merkle proof
	proof, err := issuerTree.GenerateProof(hiClaimAboutId, nil)
	assert.Nil(t, err)
	// fmt.Println(proof)
	// fmt.Println(proof.Siblings)
	// fmt.Println("len siblings", len(proof.Siblings))
	// siblings := merkletree.SiblingsFromProof(proof, issuerTree.MaxLevels())
	siblings := merkletree.SiblingsFromProof(proof)
	for i := len(siblings); i < issuerTree.MaxLevels(); i++ { // add the rest of empty levels to the siblings
		siblings = append(siblings, &merkletree.HashZero)
	}
	siblings = append(siblings, &merkletree.HashZero) // add extra level for circom compatibility
	// fmt.Println("s", siblings)
	var siblingsStr []string
	for i := 0; i < len(siblings); i++ {
		siblingsStr = append(siblingsStr, new(big.Int).SetBytes(common3.SwapEndianness(siblings[i].Bytes())).String())
	}
	jsonSiblings, err := json.Marshal(siblingsStr)
	assert.Nil(t, err)

	// fmt.Println("ROOT", issuerTree.RootKey(), new(big.Int).SetBytes(common3.SwapEndianness(issuerTree.RootKey().Bytes())))
	hvClaimAboutId, _ := claimAboutId.Entry().HValue()
	// leafKey, err := merkletree.LeafKey(hiClaimAboutId, hvClaimAboutId)
	// assert.Nil(t, err)
	// fmt.Println("LEAFKEY", leafKey, new(big.Int).SetBytes(common3.SwapEndianness(leafKey.Bytes())))

	assert.True(t, merkletree.VerifyProof(issuerTree.RootKey(), proof, hiClaimAboutId, hvClaimAboutId))

	fmt.Println("--- copy & paste into credential.test.js / multiple-claims-in-tree ---")
	fmt.Printf(`issuerRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(issuerTree.RootKey().Bytes())))
	fmt.Printf(`siblings: %s,`+"\n", jsonSiblings)
	fmt.Printf(`id: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))
	fmt.Printf(`oUserPrivateKey: "%s",`+"\n", skToBigInt(&k))
	fmt.Printf(`oSiblings: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`oClaimsTreeRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Printf(`// oRevTreeRoot: "0",` + "\n") // TMP
	fmt.Printf(`// oRootsTreeRoot: "%s"`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(rot.RootKey().Bytes())))
	fmt.Println("--- end of copy & paste to credential.test.js / multiple-claims-in-tree ---")

	fmt.Println("\nEnd of Credential multiple claims in tree test vectors 1 \n-----")

	// err = issuerTree.PrintGraphViz(nil)
	// assert.Nil(t, err)
}

func TestCredentialMultipleClaimsInTree2(t *testing.T) {
	fmt.Println("\n-------\nCredential multiple claims in tree test vectors 2:")

	nLevels := 3
	issuerNumLevels := 10

	privKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	// Create new claim
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	pk := k.Public()

	claimKOp := claims.NewClaimKeyBabyJub(pk, 1)

	clt, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)
	rot, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)

	id, err := genesis.CalculateIdGenesisMT(clt, rot, claimKOp, []merkletree.Entrier{})
	assert.Nil(t, err)

	// create Issuer tree
	issuerTree, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), issuerNumLevels)
	assert.Nil(t, err)
	// build ClaimBasic about Id
	var indexSlot [claims.IndexSlotLen]byte
	var valueSlot [claims.ValueSlotLen]byte
	copy(indexSlot[(152/8):], id.Bytes())
	claimAboutId := claims.NewClaimBasic(indexSlot, valueSlot)
	hiClaimAboutId, _ := claimAboutId.Entry().HIndex()

	// add ClaimAboutId to issuerTree
	err = issuerTree.AddClaim(claimAboutId)
	assert.Nil(t, err)

	// add padding claims
	fmt.Println(issuerTree.RootKey())
	issuerTree, err = addExtraClaims(issuerTree, 10)
	assert.Nil(t, err)
	fmt.Println(issuerTree.RootKey())

	// generate merkle proof
	proof, err := issuerTree.GenerateProof(hiClaimAboutId, nil)
	assert.Nil(t, err)
	siblings := merkletree.SiblingsFromProof(proof)
	for i := len(siblings); i < issuerTree.MaxLevels(); i++ { // add the rest of empty levels to the siblings
		siblings = append(siblings, &merkletree.HashZero)
	}
	siblings = append(siblings, &merkletree.HashZero) // add extra level for circom compatibility
	var siblingsStr []string
	for i := 0; i < len(siblings); i++ {
		siblingsStr = append(siblingsStr, new(big.Int).SetBytes(common3.SwapEndianness(siblings[i].Bytes())).String())
	}
	jsonSiblings, err := json.Marshal(siblingsStr)
	assert.Nil(t, err)

	hvClaimAboutId, _ := claimAboutId.Entry().HValue()
	assert.True(t, merkletree.VerifyProof(issuerTree.RootKey(), proof, hiClaimAboutId, hvClaimAboutId))

	fmt.Println("--- copy & paste into credential.test.js / multiple-claims-in-tree ---")
	fmt.Printf(`issuerRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(issuerTree.RootKey().Bytes())))
	fmt.Printf(`siblings: %s,`+"\n", jsonSiblings)
	fmt.Printf(`id: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(id.Bytes())))
	fmt.Printf(`oUserPrivateKey: "%s",`+"\n", skToBigInt(&k))
	fmt.Printf(`oSiblings: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`oClaimsTreeRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(clt.RootKey().Bytes())))
	fmt.Printf(`// oRevTreeRoot: "0",` + "\n") // TMP
	fmt.Printf(`// oRootsTreeRoot: "%s"`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(rot.RootKey().Bytes())))
	fmt.Println("--- end of copy & paste to credential.test.js / multiple-claims-in-tree ---")

	fmt.Println("\nEnd of Credential multiple claims in tree test vectors 2 \n-----")
}

func addExtraClaims(tree *merkletree.MerkleTree, n int) (*merkletree.MerkleTree, error) {
	for i := 0; i < n; i++ {
		indexData := []byte("padding-claim-" + strconv.Itoa(i))
		valueData := []byte("padding-claim-" + strconv.Itoa(i))
		var indexSlot [claims.IndexSlotLen]byte
		var valueSlot [claims.ValueSlotLen]byte
		copy(indexSlot[:], indexData[:])
		copy(valueSlot[:], valueData[:])
		c := claims.NewClaimBasic(indexSlot, valueSlot)
		hi, err := c.Entry().HIndex()
		if err != nil {
			return tree, err
		}
		err = tree.AddClaim(c)
		if err != nil {
			return tree, err
		}
		_, err = tree.GenerateProof(hi, nil)
		if err != nil {
			return tree, err
		}
	}
	return tree, nil
}
