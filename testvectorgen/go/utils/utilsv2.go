package utils

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
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

	// extract pubKey
	key, X, Y := ExtractPubXY(privKHex)
	it.PK = key

	// create auth claim
	authClaim, err := AuthClaimFromPubKey(X, Y)
	it.AuthClaim = authClaim

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
   "@context": [
     "https://www.w3.org/2018/credentials/v1",
     "https://w3id.org/citizenship/v1",
     "https://w3id.org/security/bbs/v1"
   ],
   "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
   "type": ["VerifiableCredential", "PermanentResidentCard"],
   "issuer": "did:example:489398593",
   "identifier": 83627465,
   "name": "Permanent Resident Card",
   "description": "Government of Example Permanent Resident Card.",
   "issuanceDate": "2019-12-03T12:19:52Z",
   "expirationDate": "2029-12-03T12:19:52Z",
   "credentialSubject": {
     "id": "did:example:b34ca6cd37bbf23",
     "type": ["PermanentResident", "Person"],
     "givenName": "JOHN",
     "familyName": "SMITH",
     "gender": "Male",
     "image": "data:image/png;base64,iVBORw0KGgokJggg==",
     "residentSince": "2015-01-01",
     "lprCategory": "C09",
     "lprNumber": "999-999-999",
     "commuterClassification": "C1",
     "birthCountry": "Bahamas",
     "birthDate": "1958-07-17"
   }
 }`

func DefaultJSONUserClaim(subject core.ID) (*merklize.Merklizer, *core.Claim, error) {
	mz, err := merklize.Merklize(context.Background(), strings.NewReader(TestClaimDocument))
	if err != nil {
		return nil, nil, err
	}

	// issue issuerClaim for user
	dataSlotA, err := core.NewElemBytesFromInt(mz.Root().BigInt())

	fmt.Println("root", mz.Root().BigInt())

	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	copy(schemaHash[:], schemaBytes)

	nonce := 10

	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(subject),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))

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
