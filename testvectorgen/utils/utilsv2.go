package utils

import (
	"context"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

type IdentityTest struct {
	ID        core.ID
	Clt       *merkletree.MerkleTree
	Ret       *merkletree.MerkleTree
	Rot       *merkletree.MerkleTree
	AuthClaim *core.Claim
	PK        *babyjub.PrivateKey
}

func (it *IdentityTest) Sign(challenge *big.Int) *babyjub.Signature {
	return it.PK.SignPoseidon(challenge)
}

func (it *IdentityTest) State(t testing.TB) *big.Int {
	state, err := core.IdenState(it.Clt.Root().BigInt(), it.Ret.Root().BigInt(), it.Rot.Root().BigInt())
	if err != nil {
		t.Fatalf("Error calculating state: %v", err)
	}
	return state
}

func (it *IdentityTest) AuthMTPStrign(t testing.TB) []string {
	p, _ := it.ClaimMTPRaw(t, it.AuthClaim)
	return PrepareSiblingsStr(p.AllSiblings(), 32)
}

func (it *IdentityTest) SignClaim(t testing.TB, claim *core.Claim) *babyjub.Signature {
	hashIndex, hashValue, err := claim.HiHv()
	if err != nil {
		t.Fatalf("can't get hash index/value from claim %v", err)
	}

	commonHash, err := poseidon.Hash([]*big.Int{hashIndex, hashValue})
	if err != nil {
		t.Fatalf("can't hash index and value")
	}

	return it.PK.SignPoseidon(commonHash)
}

func (it *IdentityTest) ClaimMTPRaw(t testing.TB, claim *core.Claim) (*merkletree.Proof, *big.Int) {
	// add auth claim to claimsMT
	hi, _, err := claim.HiHv()
	if err != nil {
		t.Fatalf("can't get claim hash index %v", err)
	}

	proof, value, err := it.Clt.GenerateProof(context.Background(), hi, nil)
	if err != nil {
		t.Fatalf("can't generate proof %v", err)
	}
	return proof, value
}

func (it *IdentityTest) ClaimMTP(t testing.TB, claim *core.Claim) (sibling []string, nodeAux NodeAuxValue) {
	// add auth claim to claimsMT
	hi, _, err := claim.HiHv()
	if err != nil {
		t.Fatalf("can't get claim index hash %v", err)
	}

	proof, _, err := it.Clt.GenerateProof(context.Background(), hi, nil)
	if err != nil {
		t.Fatalf("can't generate proof %v", err)
	}

	return PrepareProof(proof)
}

func (it *IdentityTest) ClaimRevMTPRaw(t testing.TB, claim *core.Claim) (*merkletree.Proof, *big.Int) {
	// add auth claim to claimsMT
	revNonce := claim.GetRevocationNonce()

	proof, value, err := it.Ret.GenerateProof(context.Background(), new(big.Int).SetUint64(revNonce), nil)
	if err != nil {
		t.Fatalf("can't generate proof %v", err)
	}
	return proof, value
}

func (it *IdentityTest) ClaimRevMTP(t testing.TB, claim *core.Claim) (sibling []string, nodeAux NodeAuxValue) {
	// add auth claim to claimsMT
	revNonce := claim.GetRevocationNonce()

	proof, _, err := it.Ret.GenerateProof(context.Background(), new(big.Int).SetUint64(revNonce), nil)
	if err != nil {
		t.Fatalf("can't generate proof %v", err)
	}

	return PrepareProof(proof)

}

func (it *IdentityTest) IDHash(t testing.TB) *big.Int {
	idHash, err := poseidon.Hash([]*big.Int{it.ID.BigInt()})
	if err != nil {
		t.Fatalf("can't hash id %v", err)
	}
	return idHash
}

func (it *IdentityTest) AddClaim(t *testing.T, claim *core.Claim) {
	// add auth claim to claimsMT
	hi, hv, err := claim.HiHv()
	if err != nil {
		t.Fatalf("Error calculating hi and hv: %v", err)
	}

	err = it.Clt.Add(context.Background(), hi, hv)
	if err != nil {
		t.Fatalf("Error adding claim to claimsMT: %v", err)
	}
}

func NewIdentity(t testing.TB, privKHex string) *IdentityTest {

	it := IdentityTest{}
	var err error

	// init claims tree

	it.Clt, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	if err != nil {
		t.Fatalf("Error creating Claims merkle tree: %v", err)
	}
	it.Ret, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	if err != nil {
		t.Fatalf("Error creating Revocation merkle tree: %v", err)
	}
	it.Rot, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	if err != nil {
		t.Fatalf("Error creating Roots merkle tree: %v", err)
	}

	authClaim, key, err := NewAuthClaim(privKHex)
	if err != nil {
		t.Fatalf("Error creating Auth claim: %v", err)
	}

	it.AuthClaim = authClaim
	it.PK = key

	// add auth claim to claimsMT
	hi, hv, err := authClaim.HiHv()

	err = it.Clt.Add(context.Background(), hi, hv)
	if err != nil {
		t.Fatalf("Error adding Auth claim to Claims merkle tree: %v", err)
	}

	state := it.State(t)

	identifier, err := IDFromState(state)
	if err != nil {
		t.Fatalf("Error generating id from state: %v", err)
	}

	it.ID = *identifier

	return &it
}

type NodeAuxValue struct {
	Key   string
	Value string
	NoAux string
}

func getNodeAuxValue(p *merkletree.Proof) NodeAuxValue {

	// proof of inclusion
	if p.Existence {
		return NodeAuxValue{
			Key:   merkletree.HashZero.BigInt().String(),
			Value: merkletree.HashZero.BigInt().String(),
			NoAux: "0",
		}
	}

	// proof of non-inclusion (NodeAux exists)
	if p.NodeAux != nil && p.NodeAux.Value != nil && p.NodeAux.Key != nil {
		return NodeAuxValue{
			Key:   p.NodeAux.Key.BigInt().String(),
			Value: p.NodeAux.Value.BigInt().String(),
			NoAux: "0",
		}
	}
	// proof of non-inclusion (NodeAux does not exist)
	return NodeAuxValue{
		Key:   merkletree.HashZero.BigInt().String(),
		Value: merkletree.HashZero.BigInt().String(),
		NoAux: "1",
	}
}
