package linked

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"test/utils"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/stretchr/testify/require"
)

const (
	userPK = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
)

type Inputs struct {
	LinkNonce            string             `json:"linkNonce"`
	IssuerClaim          *core.Claim        `json:"issuerClaim"`
	ClaimSchema          string             `json:"claimSchema"`
	ClaimPathMtp         [][]string         `json:"claimPathMtp"`
	ClaimPathMtpNoAux    []string           `json:"claimPathMtpNoAux"` // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi    []*merkletree.Hash `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv    []*merkletree.Hash `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathKey         []string           `json:"claimPathKey"`      // hash of path in merklized json-ld document
	ClaimPathValue       []string           `json:"claimPathValue"`    // value in this path in merklized json-ld document
	SlotIndex            []int              `json:"slotIndex"`
	Operator             []int              `json:"operator"`
	Value                [][]string         `json:"value"`
	ActualValueArraySize []int              `json:"valueArraySize"`
}

type Outputs struct {
	LinkID               string   `json:"linkID"`
	Merklized            int      `json:"merklized"`
	OperatorOutput       []string `json:"operatorOutput"`
	CircuitQueryHash     []string `json:"circuitQueryHash"`
	ActualValueArraySize []int    `json:"valueArraySize"`
}

type TestData struct {
	Desc string  `json:"desc"`
	In   Inputs  `json:"inputs"`
	Out  Outputs `json:"expOut"`
}

func Test_OneQuery(t *testing.T) {
	desc := "Linked query count: 1,  operator: LT"

	queries := []Query{
		{
			Operator: utils.LT, // lt
			Values:   []*big.Int{new(big.Int).SetInt64(20020101)},
		},
	}
	generate(t, desc, "linked/one_query", queries)
}
func Test_TwoQueries(t *testing.T) {
	desc := "Linked query count: 2,  operator: LT , NE"

	queries := []Query{
		{
			Operator: utils.LT,
			Values:   []*big.Int{new(big.Int).SetInt64(20020101)},
		},
		{
			Operator: utils.NE,
			Values:   []*big.Int{new(big.Int).SetInt64(20030101)},
		},
	}
	generate(t, desc, "linked/two_queries", queries)
}

// Query represents basic request to claim field with MTP and without
type Query struct {
	Operator int
	Values   []*big.Int
}

func generate(t *testing.T, desc string, fileName string, queries []Query) {
	var err error

	isJSONLD := true
	isZeroSubjClaim := false

	linkNonce := "1"

	user := utils.NewIdentity(t, userPK)
	subjectID := user.ID

	var claim *core.Claim
	var mz *merklize.Merklizer
	var claimPathMtp []string
	var claimPathMtpNoAux, claimPathMtpAuxHi, claimPathMtpAuxHv, claimPathKey, claimPathValue string
	var pathKey *big.Int

	var merklized int
	var slotIndex = 0

	if isJSONLD {
		mz, claim = utils.DefaultJSONNormalUserClaim(t, subjectID)
		path, err := merklize.NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject",
			"https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#birthday")
		require.NoError(t, err)
		jsonP, value, err := mz.Proof(context.Background(), path)
		require.NoError(t, err)
		valueKey, err := value.MtEntry()
		require.NoError(t, err)
		claimPathValue = valueKey.String()

		var claimJSONLDProofAux utils.NodeAuxValue
		claimPathMtp, claimJSONLDProofAux = utils.PrepareProof(jsonP, utils.ClaimLevels)
		claimPathMtpNoAux = claimJSONLDProofAux.NoAux
		claimPathMtpAuxHi = claimJSONLDProofAux.Key
		claimPathMtpAuxHv = claimJSONLDProofAux.Value
		pathKey, err = path.MtEntry()
		require.NoError(t, err)
		claimPathKey = pathKey.String()

		//valueInput = utils.PrepareStrArray([]string{claimPathValue}, 64)
		merklized = 1

	} else {
		var subjValue *big.Int
		if isZeroSubjClaim {
			subjValue = big.NewInt(0)
		}
		claim = utils.DefaultUserClaim(t, subjectID, subjValue)
		claimPathMtp = utils.PrepareStrArray([]string{}, 32)
		claimPathMtpNoAux = "0"
		claimPathMtpAuxHi = "0"
		claimPathMtpAuxHv = "0"
		claimPathKey = "0"
		claimPathValue = "0"
		merklized = 0
		pathKey = big.NewInt(0)

		slotIndex = 2
	}

	hI, err := merkletree.NewHashFromString(claimPathMtpAuxHi)
	require.NoError(t, err)
	hV, err := merkletree.NewHashFromString(claimPathMtpAuxHv)
	require.NoError(t, err)

	s := Inputs{}

	s.LinkNonce = linkNonce
	s.IssuerClaim = claim
	s.ClaimSchema = claim.GetSchemaHash().BigInt().String()
	s.ClaimPathMtp = make([][]string, 10)
	s.ClaimPathMtpNoAux = make([]string, 10)
	s.ClaimPathMtpAuxHi = make([]*merkletree.Hash, 10)
	s.ClaimPathMtpAuxHv = make([]*merkletree.Hash, 10)
	s.ClaimPathKey = make([]string, 10)
	s.ClaimPathValue = make([]string, 10)
	s.SlotIndex = make([]int, 10)
	s.Operator = make([]int, 10)
	s.Value = make([][]string, 10)
	s.ActualValueArraySize = make([]int, 10)

	for i := 0; i < 10; i++ {
		if i >= 0 {
			s.ClaimPathMtp[i] = utils.PrepareSiblingsStr([]*merkletree.Hash{}, 32)

			s.ClaimPathMtpNoAux[i] = "0"
			s.ClaimPathMtpAuxHi[i] = &merkletree.HashZero
			s.ClaimPathMtpAuxHv[i] = &merkletree.HashZero

			s.ClaimPathKey[i] = "0"
			s.ClaimPathValue[i] = "0"

			s.SlotIndex[i] = 0
			s.Operator[i] = 0

			values, err := PrepareCircuitArrayValues(make([]*big.Int, 0), 64)
			if err != nil {
				continue
			}
			s.Value[i] = bigIntArrayToStringArray(values)
			s.ActualValueArraySize[i] = 0
			continue
		}
	}

	for i, query := range queries {
		s.Operator[i] = query.Operator
		s.SlotIndex[i] = slotIndex
		s.ClaimPathMtp[i] = claimPathMtp
		s.ClaimPathMtpNoAux[i] = claimPathMtpNoAux
		s.ClaimPathMtpAuxHi[i] = hI
		s.ClaimPathMtpAuxHv[i] = hV
		s.ClaimPathKey[i] = claimPathKey
		s.ClaimPathValue[i] = claimPathValue
		s.ActualValueArraySize[i] = len(query.Values)
		values, err := PrepareCircuitArrayValues(query.Values, 64)
		if err != nil {
			continue
		}
		s.Value[i] = bigIntArrayToStringArray(values)

	}

	l, _ := CalculateLinkIDBigInt(linkNonce, claim)

	out := Outputs{
		Merklized:            merklized,
		LinkID:               l.String(),
		OperatorOutput:       fillOperatorOutput(queries),
		CircuitQueryHash:     fillCircuitQueryHash(s, merklized, queries),
		ActualValueArraySize: s.ActualValueArraySize,
	}

	require.NoError(t, err)

	jsonData, err := json.Marshal(TestData{
		desc,
		s,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonData))
}

func fillOperatorOutput(queries []Query) []string {

	arr := make([]string, 10)
	for i, _ := range arr {
		if i < len(queries) && queries[i].Operator == utils.SD {
			arr[i] = queries[i].Values[0].String()
		} else {
			arr[i] = "0"
		}
	}
	return arr
}

func fillCircuitQueryHash(s Inputs, merklized int, queries []Query) []string {
	merklizedBigInt := big.NewInt(0).SetInt64(int64(merklized))
	schema, _ := new(big.Int).SetString(s.ClaimSchema, 10)

	arr := make([]string, 10)
	for i, _ := range arr {
		if i < len(queries) {
			claimPathKey, _ := new(big.Int).SetString(s.ClaimPathKey[i], 10)

			queryHash, _ := CalculateQueryHash(
				queries[i].Values,
				schema,
				s.SlotIndex[i],
				s.Operator[i],
				claimPathKey,
				merklizedBigInt,
			)

			arr[i] = queryHash.String()
		} else {
			claimPathKey, _ := new(big.Int).SetString(s.ClaimPathKey[i], 10)

			queryHash, _ := CalculateQueryHash(
				[]*big.Int{},
				schema,
				0,
				0,
				claimPathKey,
				merklizedBigInt,
			)
			arr[i] = queryHash.String()

		}

	}
	return arr
}
func CalculateQueryHash(
	values []*big.Int,
	schemaHash *big.Int,
	slotIndex int,
	operator int,
	claimPathKey *big.Int,
	merklized *big.Int,
) (*big.Int, error) {

	valArrSize := big.NewInt(int64(len(values)))
	circuitValues, err := PrepareCircuitArrayValues(values, 64)
	if err != nil {
		return nil, err
	}

	valueHash, err := poseidon.SpongeHashX(circuitValues, 6)
	if err != nil {
		return nil, err
	}
	firstPart, err := poseidon.Hash([]*big.Int{
		schemaHash,
		big.NewInt(int64(slotIndex)),
		big.NewInt(int64(operator)),
		claimPathKey,
		merklized,
		valueHash,
	})
	if err != nil {
		return nil, err
	}
	return poseidon.Hash([]*big.Int{
		firstPart,
		valArrSize,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	})

}
func PrepareCircuitArrayValues(arr []*big.Int, size int) ([]*big.Int, error) {
	if len(arr) > size {
		return nil, errors.New("ff")
	}

	// Add the empty values
	for i := len(arr); i < size; i++ {
		arr = append(arr, new(big.Int))
	}

	return arr, nil
}
func CalculateLinkIDBigInt(linkNonce string, claim *core.Claim) (*big.Int, error) {
	if linkNonce == "0" {
		return nil, nil
	}

	nonceInt, ok := big.NewInt(0).SetString(linkNonce, 10)

	if !ok {
		return nil, fmt.Errorf("invalid linkNonce value: '%s'", linkNonce)
	}

	hi, hv, err := claim.HiHv()
	if err != nil {
		return nil, err
	}

	claimHash, err := poseidon.Hash([]*big.Int{hi, hv})
	if err != nil {
		return nil, err
	}

	linkID, err := poseidon.Hash([]*big.Int{claimHash, nonceInt})
	if err != nil {
		return nil, err
	}

	return linkID, nil
}
func bigIntArrayToStringArray(array []*big.Int) []string {
	res := make([]string, 0)
	for i := range array {
		res = append(res, array[i].String())
	}
	return res
}
