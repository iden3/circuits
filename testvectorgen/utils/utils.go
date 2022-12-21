package utils

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/iden3/go-schema-processor/processor"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
	"crypto/rand"


	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/merklize"
)

func DefaultJSONUserClaim(t testing.TB, subject core.ID) (*merklize.Merklizer, *core.Claim) {
	mz, err := merklize.MerklizeJSONLD(context.Background(), strings.NewReader(TestClaimDocument))
	if err != nil {
		t.Fatalf("failed marklize claim: %v", err)
	}

	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	if err != nil {
		t.Fatalf("failed decode schema hash string %v", err)
	}
	copy(schemaHash[:], schemaBytes)

	nonce := 10

	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(subject),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)),
		core.WithIndexMerklizedRoot(mz.Root().BigInt()))

	if err != nil {
		t.Fatalf("failed generate core claim %v", err)
	}

	return mz, claim
}

func DefaultUserClaim(t testing.TB, subject core.ID) *core.Claim {
	dataSlotA, err := core.NewElemBytesFromInt(big.NewInt(10))
	if err != nil {
		t.Fatalf("failed get NewElemBytesFromInt %v", err)
	}

	nonce := 1
	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("ce6bb12c96bfd1544c02c289c6b4b987")
	if err != nil {
		t.Fatalf("failed decode schema hash %v", err)
	}
	copy(schemaHash[:], schemaBytes)

	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(subject),
		core.WithIndexData(dataSlotA, core.ElemBytes{}),
		core.WithExpirationDate(time.Unix(1669884010, 0)), //Thu Dec 01 2022 08:40:10 GMT+0000
		core.WithRevocationNonce(uint64(nonce)))
	if err != nil {
		t.Fatalf("failed create new claim %v", err)
	}

	return claim

}

func PrepareProof(proof *merkletree.Proof) ([]string, NodeAuxValue) {
	return PrepareSiblingsStr(proof.AllSiblings(), 32), getNodeAuxValue(proof)
}

func ExtractPubXY(privKHex string) (key *babyjub.PrivateKey, x, y *big.Int) {
	// Extract pubKey
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	pk := k.Public()
	return &k, pk.X, pk.Y
}

func HashToStr(siblings []*merkletree.Hash) []string {
	siblingsStr := make([]string, len(siblings))
	for i, sibling := range siblings {
		siblingsStr[i] = sibling.BigInt().String()
	}
	return siblingsStr
}

func PrepareStrArray(siblings []string, levels int) []string {
	// Add the rest of empty levels to the array
	for i := len(siblings); i < levels; i++ {
		siblings = append(siblings, "0")
	}
	return siblings
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

func NewAuthClaim(t testing.TB, privKHex string) (auth *core.Claim, key *babyjub.PrivateKey) {
	// extract pubKey
	key, X, Y := ExtractPubXY(privKHex)

	// create auth claim
	authClaim, err := AuthClaimFromPubKey(X, Y)
	if err != nil {
		t.Fatalf("can't create auth claim from pub key %v", err)
	}
	return authClaim, key
}

func AuthClaimFromPubKey(X, Y *big.Int) (*core.Claim, error) {
	var schemaHash core.SchemaHash
	//schemaEncodedBytes, _ := hex.DecodeString("ca938857241db9451ea329256b9c06e5") // V1
	schemaEncodedBytes, _ := hex.DecodeString("013fd3f623559d850fb5b02ff012d0e2") // V2
	copy(schemaHash[:], schemaEncodedBytes)

	// NOTE: We take nonce as hash of public key to make it random
	// We don't use random number here because this test vectors will be used for tests
	// and have randomization inside tests is usually a bad idea
	revNonce, err := poseidon.Hash([]*big.Int{X})
	if err != nil {
		return nil, err
	}

	return core.NewClaim(schemaHash,
		core.WithIndexDataInts(X, Y),
		core.WithRevocationNonce(revNonce.Uint64()))
}

func CreateStateSecretClaim(t testing.TB, subject core.ID) *core.Claim {
	secret := big.NewInt(443)

	schemauUrl := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/stateSecret.json-ld"
	schemaType := "StateSecretCredential"

	data := []byte(`{ "secret": ` + secret.String() + `, "documentType": 1}`)

	builder := NewBuilder()
	slots, schema, err := builder.Process(schemauUrl, schemaType, data)
	if err!= nil {
		t.Fatalf("err on builder.process. err: %v", err)
	}
	claimNonce, err := Rand()
	claimReq := &CoreClaimData{
		EncodedSchema:   encodedSchema,
		Slots:           *slots,
		SubjectID:       "123",
		Expiration:      12345678888,
		Version:         1,
		Nonce:           &claimNonce,
		SubjectPosition: cReq.SubjectPosition,
	}


}

type CoreClaimData struct {
	EncodedSchema   string
	Slots           processor.ParsedSlots
	SubjectID       string
	Expiration      int64
	Version         uint32
	Nonce           *uint64
	SubjectPosition string
}

func GenerateCoreClaim(req *CoreClaimData) (*core.Claim, error) {

	var revNonce *uint64
	r, err := Rand()
	if err != nil {
		return nil, err
	}

	revNonce = &r
	if req.Nonce != nil {
		revNonce = req.Nonce
	}

	var coreClaim *core.Claim

	var sh core.SchemaHash
	schemaBytes, err := hex.DecodeString(req.EncodedSchema)
	if err != nil {
		return nil, err
	}
	copy(sh[:], schemaBytes)
	coreClaim, err = core.NewClaim(sh,
		core.WithIndexDataBytes(req.Slots.IndexA, req.Slots.IndexB),
		core.WithValueDataBytes(req.Slots.ValueA, req.Slots.ValueB),
		core.WithRevocationNonce(*revNonce),
		core.WithVersion(req.Version))
	if err != nil {
		return nil, err
	}

	if req.SubjectID != "" {
		var userID core.ID
		userID, err = core.IDFromString(req.SubjectID)
		if err != nil {
			return nil, err
		}

		switch req.SubjectPosition {
		case "", SubjectPositionIndex:
			coreClaim.SetIndexID(userID)
		case SubjectPositionValue:
			coreClaim.SetValueID(userID)
		default:
			return nil, fmt.Errorf("unknown subject position")
		}
	}

	if req.Expiration != 0 {
		coreClaim.SetExpirationDate(time.Unix(req.Expiration, 0))
	}
	return coreClaim, nil
}

func Rand() (uint64, error) {
	var buf [8]byte
	// TODO: this was changed because revocation nonce is cut in dart / js if number is too big
	_, err := rand.Read(buf[:4])

	return binary.LittleEndian.Uint64(buf[:]), err
}

const (
	// SubjectPositionIndex save subject in index part of claim. By default.
	SubjectPositionIndex = "index"
	// SubjectPositionValue save subject in value part of claim.
	SubjectPositionValue = "value"

	BabyJubSignatureType = "BJJSignature2021"
)

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
