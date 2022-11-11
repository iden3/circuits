package utils

import (
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/merklize"
	"test/crypto/primitive"
)

type IdentityTest struct {
	ID        core.ID
	Clt       *merkletree.MerkleTree
	Ret       *merkletree.MerkleTree
	Rot       *merkletree.MerkleTree
	AuthClaim *core.Claim
	PK        *babyjub.PrivateKey
}

func (it *IdentityTest) SignBBJJ(challenge []byte) (*babyjub.Signature, error) {
	// sign challenge
	return SignBBJJ(it.PK, challenge)
}

func (it *IdentityTest) State() (*big.Int, error) {
	return core.IdenState(it.Clt.Root().BigInt(), it.Ret.Root().BigInt(), it.Rot.Root().BigInt())
}

func (it *IdentityTest) AuthMTPStrign() (proof []string, err error) {
	p, _, err := it.ClaimMTPRaw(it.AuthClaim)
	return PrepareSiblingsStr(p.AllSiblings(), 32), err
}

func (it *IdentityTest) SignClaimBBJJ(claim *core.Claim) (*babyjub.Signature, error) {
	hashIndex, hashValue, err := claim.HiHv()
	if err != nil {
		return nil, err
	}

	commonHash, err := poseidon.Hash([]*big.Int{hashIndex, hashValue})
	if err != nil {
		return nil, err
	}

	bjjSigner := primitive.NewBJJSigner(it.PK)
	sigBytes, err := bjjSigner.Sign(commonHash.Bytes())
	if err != nil {
		return nil, err
	}

	var sig [64]byte
	copy(sig[:], sigBytes)
	return new(babyjub.Signature).Decompress(sig)

}

func (it *IdentityTest) ClaimMTPRaw(claim *core.Claim) (proof *merkletree.Proof, value *big.Int, err error) {
	// add auth claim to claimsMT
	hi, _, err := claim.HiHv()
	if err != nil {
		return nil, nil, err
	}

	return it.Clt.GenerateProof(context.Background(), hi, nil)
}

func (it *IdentityTest) ClaimMTP(claim *core.Claim) (sibling []string, nodeAux *NodeAuxValue, err error) {
	// add auth claim to claimsMT
	hi, _, err := claim.HiHv()
	if err != nil {
		return nil, nil, err
	}

	proof, _, err := it.Clt.GenerateProof(context.Background(), hi, nil)
	if err != nil {
		return nil, nil, err
	}

	sib, aux := PrepareProof(proof)
	return sib, &aux, err
}

func (it *IdentityTest) ClaimRevMTPRaw(claim *core.Claim) (proof *merkletree.Proof, value *big.Int, err error) {
	// add auth claim to claimsMT
	revNonce := claim.GetRevocationNonce()

	return it.Ret.GenerateProof(context.Background(), new(big.Int).SetUint64(revNonce), nil)
}

func (it *IdentityTest) ClaimRevMTP(claim *core.Claim) (sibling []string, nodeAux *NodeAuxValue, err error) {
	// add auth claim to claimsMT
	revNonce := claim.GetRevocationNonce()

	proof, _, err := it.Ret.GenerateProof(context.Background(), new(big.Int).SetUint64(revNonce), nil)
	if err != nil {
		return nil, nil, err
	}

	sib, aux := PrepareProof(proof)
	return sib, &aux, err

}

func (it *IdentityTest) IDHash() *big.Int {
	idHash, err := poseidon.Hash([]*big.Int{it.ID.BigInt()})
	if err != nil {
		panic(err)
	}
	return idHash
}

func NewIdentity(privKHex string) (*IdentityTest, error) {

	it := IdentityTest{}
	var err error

	// init claims tree

	it.Clt, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 4)
	if err != nil {
		return nil, err
	}
	it.Ret, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 4)
	if err != nil {
		return nil, err
	}
	it.Rot, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 4)
	if err != nil {
		return nil, err
	}

	authClaim, key, err := NewAuthClaim(privKHex)
	if err != nil {
		return nil, err
	}

	it.AuthClaim = authClaim
	it.PK = key

	// add auth claim to claimsMT
	hi, hv, err := authClaim.HiHv()

	err = it.Clt.Add(context.Background(), hi, hv)
	if err != nil {
		return nil, err
	}

	state, err := it.State()
	if err != nil {
		return nil, err
	}

	identifier, err := IDFromState(state)
	if err != nil {
		return nil, err
	}

	it.ID = *identifier

	return &it, nil
}

func NewAuthClaim(privKHex string) (auth *core.Claim, key *babyjub.PrivateKey, err error) {
	// extract pubKey
	key, X, Y := ExtractPubXY(privKHex)

	// create auth claim
	authClaim, err := AuthClaimFromPubKey(X, Y)
	if err != nil {
		return nil, nil, err
	}
	return authClaim, key, nil
}

func IDFromState(state *big.Int) (*core.ID, error) {
	typ, err := core.BuildDIDType(core.DIDMethodIden3, core.NoChain, core.NoNetwork)
	if err != nil {
		return nil, err
	}
	// create new identity
	return core.IdGenesisFromIdenState(typ, state)
}

func PrepareSiblingsStr(siblings []*merkletree.Hash, levels int) []string {
	// siblings := mtproof.AllSiblings()
	// Add the rest of empty levels to the siblings
	for i := len(siblings); i < levels; i++ {
		siblings = append(siblings, &merkletree.HashZero)
	}
	return HashToStr(siblings)
}

func HashToStr(siblings []*merkletree.Hash) []string {
	siblingsStr := make([]string, len(siblings))
	for i, sibling := range siblings {
		siblingsStr[i] = sibling.BigInt().String()
	}
	return siblingsStr
}

func DefaultUserClaim(subject core.ID) (*core.Claim, error) {
	dataSlotA, _ := core.NewElemBytesFromInt(big.NewInt(10))
	nonce := 1
	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	if err != nil {
		return nil, err
	}
	copy(schemaHash[:], schemaBytes)

	return core.NewClaim(
		schemaHash,
		core.WithIndexID(subject),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))

}

const TestClaimDocument = `{
  "id": "8b71762d-8744-4237-9d48-4aba63848e90",
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld",
    "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld"
  ],
  "@type": [
    "VerifiableCredential",
    "Iden3Credential",
    "KYCAgeCredential"
  ],
  "expirationDate": "2361-03-21T21:14:48+02:00",
  "updatable": false,
  "version": 0,
  "rev_nonce": 127366661,
  "credentialSubject": {
    "birthday": 19960424,
    "documentType": 1,
    "id": "did:iden3:polygon:mumbai:wyFiV4w71QgWPn6bYLsZoysFay66gKtVa9kfu6yMZ",
    "type": "KYCAgeCredential"
  },
  "credentialStatus": {
    "id": "http://localhost:8001/api/v1/identities/1195DjqzhZ9zpHbezahSevDMcxN41vs3Y6gb4noRW/claims/revocation/status/127366661",
    "type": "Iden3SparseMerkleTreeProof"
  },
  "subject_position": "index",
  "credentialSchema": {
    "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld",
    "type": "KYCAgeCredential"
  },
  "merklizedRootPosition": "index",
  "proof": [
    {
      "type": "BJJSignature2021",
      "issuer_data": {
        "id": "did:iden3:polygon:mumbai:x2Uw18ATvY7mEsgfrrDipBmQQdPWAao4NmF56wGvp",
        "state": {
          "claims_tree_root": "feb0be3ec46d2c1be2c6dc1c853e1d8a7dbf6b100682fc07dd0634fe8ea82b26",
          "value": "0a12a41a5a0310e2b19a775509a430bfae9e7cf9769aaaa2e35bcc4d4b113e07"
        },
        "auth_claim": [
          "304427537360709784173770334266246861770",
          "0",
          "15617506294650956210680908108123934928756816089326409752193546503042051388780",
          "19048678283950551654871559449894565507673603294047370154250506544091413152142",
          "0",
          "0",
          "0",
          "0"
        ],
        "mtp": {
          "existence": true,
          "siblings": []
        },
        "revocation_status": {
          "id": "http://localhost:8001/api/v1/identities/1195DjqzhZ9zpHbezahSevDMcxN41vs3Y6gb4noRW/claims/revocation/status/0",
          "type": "Iden3SparseMerkleTreeProof"
        }
      },
      "signature": "716c532dc08c14b10214d95fe3e0f85704114a060a2d4cdaff1938a1c2356681ebff57b4efe51dae00094924c6d8835b8de819369bd9473f02f48fc3b4959304"
    }
  ]
}`

func DefaultJSONUserClaim(subject core.ID) (*merklize.Merklizer, *core.Claim, error) {
	mz, err := merklize.MerklizeJSONLD(context.Background(), strings.NewReader(TestClaimDocument))
	if err != nil {
		return nil, nil, err
	}

	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	copy(schemaHash[:], schemaBytes)

	nonce := 10

	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(subject),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)),
		core.WithIndexMerklizedRoot(mz.Root().BigInt()))

	return mz, claim, err
}

func PrepareProof(proof *merkletree.Proof) ([]string, NodeAuxValue) {
	return PrepareSiblingsStr(proof.AllSiblings(), 32), getNodeAuxValue(proof)
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

func SaveTestVector(t *testing.T, fileName string, data string) {
	t.Helper()
	path := "testdata/" + fileName + ".json"

	f, err := os.Create(path)
	defer f.Close()
	if err != nil {
		t.Fatalf("Error writing to file %s: %s", path, err)
	}

	_, err = f.WriteString(data)
	if err != nil {
		t.Fatalf("Error writing to file %s: %s", path, err)
	}
}

// List of available operators.
const (
	NOOP int = iota // No operation, skip query verification in circuit
	EQ
	LT
	GT
	IN
	NIN
)
