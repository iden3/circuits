package utils

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/loaders"
	"github.com/iden3/go-schema-processor/v2/merklize"
)

func DefaultJSONUserClaim(t testing.TB, subject core.ID) (*merklize.Merklizer, *core.Claim) {
	opts := loaders.WithEmbeddedDocumentBytes(w3cSchemaURL, w3cSchemaBody)
	memoryCacheEngine, err := loaders.NewMemoryCacheEngine(opts)
	if err != nil {
		log.Fatalf("failed init memory cache engine: %v", err)
	}
	documentLoader := loaders.NewDocumentLoader(nil, "https://ipfs.io/",
		loaders.WithCacheEngine(memoryCacheEngine))

	merklizeOpts := []merklize.MerklizeOption{
		merklize.WithDocumentLoader(documentLoader),
	}
	mz, err := merklize.MerklizeJSONLD(context.Background(), strings.NewReader(TestClaimDocument), merklizeOpts...)
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

func DefaultJSONNormalUserClaim(t testing.TB, subject core.ID) (*merklize.Merklizer, *core.Claim) {
	opts := loaders.WithEmbeddedDocumentBytes(w3cSchemaURL, w3cSchemaBody)
	memoryCacheEngine, err := loaders.NewMemoryCacheEngine(opts)
	if err != nil {
		log.Fatalf("failed init memory cache engine: %v", err)
	}
	documentLoader := loaders.NewDocumentLoader(nil, "https://ipfs.io/",
		loaders.WithCacheEngine(memoryCacheEngine))

	merklizeOpts := []merklize.MerklizeOption{
		merklize.WithDocumentLoader(documentLoader),
	}
	mz, err := merklize.MerklizeJSONLD(context.Background(), strings.NewReader(TestNormalClaimDocument), merklizeOpts...)
	if err != nil {
		t.Fatalf("failed marklize claim: %v", err)
	}

	schemaHash, err := core.NewSchemaHashFromHex("508991bcf0336ba99935ef498d797ec9")
	if err != nil {
		t.Fatalf("failed marklize claim: %v", err)
	}

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


func DefaultUserClaim(t testing.TB, subject core.ID, subjValue *big.Int) *core.Claim {
	value := big.NewInt(10)
	if subjValue != nil {
		value = subjValue
	}
	dataSlotA, err := core.NewElemBytesFromInt(value)
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

func GenerateNewStateCommitmentClaim(t testing.TB, secret *big.Int) *core.Claim {
	dataSlotA, err := core.NewElemBytesFromInt(secret)
	if err != nil {
		t.Fatalf("failed get NewElemBytesFromInt %v", err)
	}

	var schemaHash core.SchemaHash
	schemaBytes, err := hex.DecodeString("b55fa22ddacd3459bee10699dd025405")
	if err != nil {
		t.Fatalf("failed decode schema hash %v", err)
	}
	copy(schemaHash[:], schemaBytes)

	claim, err := core.NewClaim(schemaHash, core.WithValueData(dataSlotA, core.ElemBytes{}))
	if err != nil {
		t.Fatalf("failed create new claim %v", err)
	}

	return claim
}

func PrepareProof(proof *merkletree.Proof, levels int) ([]string, NodeAuxValue) {
	return PrepareSiblingsStr(proof.AllSiblings(), levels), getNodeAuxValue(proof)
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
	typ, err := core.BuildDIDType(core.DIDMethodIden3, core.Polygon, core.Mumbai)
	if err != nil {
		return nil, err
	}
	// create new identity
	return core.NewIDFromIdenState(typ, state)
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

	// NOTE: We take nonce as hash of public key to make it random
	// We don't use random number here because this test vectors will be used for tests
	// and have randomization inside tests is usually a bad idea
	revNonce, err := poseidon.Hash([]*big.Int{X})
	if err != nil {
		return nil, err
	}

	return core.NewClaim(core.AuthSchemaHash,
		core.WithIndexDataInts(X, Y),
		core.WithRevocationNonce(revNonce.Uint64()))
}

func SaveTestVector(t *testing.T, fileName string, data string) {
	t.Helper()
	dir := "testdata"

	fullFilePath := path.Join(dir, fileName+".json")
	directoryPath := filepath.Dir(fullFilePath)

	err := os.MkdirAll(directoryPath, 0777)
	if err != nil {
		t.Fatal("Error creatind directory testdata", err)
	}

	file, err := os.Create(fullFilePath)

	if err != nil {
		t.Fatalf("Error writing to file %s: %s", fileName, err)
	}

	_, err = file.WriteString(data)
	if err != nil {
		t.Fatalf("Error writing to file %s: %s", fileName, err)
	}
}

// BatchSize defined by poseidon hash implementation in Solidity
const BatchSize = 5

func FromStringArrayToBigIntArray(values []string) []*big.Int {
	bigInts := make([]*big.Int, len(values))
	for i, s := range values {
		bigInts[i], _ = new(big.Int).SetString(s, 10)
	}
	return bigInts
}

// PoseidonHashValue returns the solidity and circom implementation of poseidon hash
func PoseidonHashValue(values []*big.Int) (*big.Int, error) {

	if values == nil {
		return nil, fmt.Errorf("values not provided")
	}

	if len(values) == 0 {
		return nil, fmt.Errorf("empty values")
	}

	iterationCount := 0
	var err error
	getValueByIndex := func(arr []*big.Int, idx, length int) *big.Int {
		if idx < length {
			return arr[idx]
		}
		return big.NewInt(0)
	}
	l := len(values)
	hashFnBatchSize := 6
	// first iteration to get the first hash  (6 elements)
	fullHash, err := poseidon.Hash([]*big.Int{
		getValueByIndex(values, 0, l),
		getValueByIndex(values, 1, l),
		getValueByIndex(values, 2, l),
		getValueByIndex(values, 3, l),
		getValueByIndex(values, 4, l),
		getValueByIndex(values, 5, l),
	})

	restLength := l - hashFnBatchSize
	if restLength > BatchSize {
		r := restLength % BatchSize
		diff := BatchSize - r
		iterationCount = (restLength + diff) / BatchSize
	}

	if err != nil {
		return nil, err
	}

	for i := 0; i < iterationCount; i++ {
		elemIdx := i*BatchSize + hashFnBatchSize
		fullHash, err = poseidon.Hash([]*big.Int{
			fullHash,
			getValueByIndex(values, elemIdx, l),
			getValueByIndex(values, elemIdx+1, l),
			getValueByIndex(values, elemIdx+2, l),
			getValueByIndex(values, elemIdx+3, l),
			getValueByIndex(values, elemIdx+4, l),
		})
		if err != nil {
			return nil, err
		}
	}

	return fullHash, nil
}

// CalculateLinkID returns linkID calculated from linkNonce and claim
func CalculateLinkID(linkNonce string, claim *core.Claim) (string, error) {
	if linkNonce == "0" {
		return "0", nil
	}

	nonceInt, ok := big.NewInt(0).SetString(linkNonce, 10)

	if !ok {
		return "", fmt.Errorf("invalid linkNonce value: '%s'", linkNonce)
	}

	hi, hv, err := claim.HiHv()
	if err != nil {
		return "", err
	}

	claimHash, err := poseidon.Hash([]*big.Int{hi, hv})
	if err != nil {
		return "", err
	}

	linkID, err := poseidon.Hash([]*big.Int{claimHash, nonceInt})
	if err != nil {
		return "", err
	}

	return linkID.String(), nil
}

// CalculateNullify returns nullify operator
func CalculateNullify(genesisID, claimSubjectProfileNonce, claimSchema, verifierID, nullifierSessionID *big.Int) (string, error) {
	if claimSubjectProfileNonce == big.NewInt(0) {
		return "0", nil
	}
	if verifierID == big.NewInt(0) {
		return "0", nil
	}

	nullifier, err := poseidon.Hash([]*big.Int{genesisID, claimSubjectProfileNonce, claimSchema, verifierID, nullifierSessionID})
	if err != nil {
		return "", err
	}

	return nullifier.String(), nil
}

func GetValueArraySizeForOperator(operator int) int {
	result := 0
	oneArrLengthOps := []int{1, 2, 3, 6, 7, 8, 11}
	twoArrLengthOps := []int{9, 10}
	maxArrLengthOps := []int{4, 5}

	if contains(oneArrLengthOps, operator) {
		return 1
	}
	if contains(twoArrLengthOps, operator) {
		return 2
	}
	if contains(maxArrLengthOps, operator) {
		return 64
	}
	return result
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
