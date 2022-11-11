package claimUtils

import (
	"encoding/json"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/stretchr/testify/require"
)

type ClaimMerklizeIn struct {
	Claim *core.Claim `json:"claim"`
}

type ClaimMerklizeOut struct {
	Out  *big.Int `json:"out"`
	Flag *big.Int `json:"flag"`
}

type TestDataSigV2 struct {
	Desc string           `json:"desc"`
	In   ClaimMerklizeIn  `json:"inputs"`
	Out  ClaimMerklizeOut `json:"expOut"`
}

func TestClaimUtils_getClaimMerklizeFlag(t *testing.T) {
	c, err := core.NewClaim(core.SchemaHash{})
	require.NoError(t, err)

	c.SetFlagMerklize(core.MerklizePositionIndex)
	c.SetIndexDataInts(big.NewInt(999), nil)

	out := TestDataSigV2{
		Desc: "Test claim merklize flag",
		In: ClaimMerklizeIn{
			Claim: c,
		},
		Out: ClaimMerklizeOut{
			Out:  big.NewInt(999),
			Flag: big.NewInt(1),
		},
	}

	json, err := json.Marshal(out)
	require.NoError(t, err)
	t.Log(string(json))
}

func TestClaimUtils_getClaimMerklizeFlag_Value(t *testing.T) {
	c, err := core.NewClaim(core.SchemaHash{})
	require.NoError(t, err)

	c.SetFlagMerklize(core.MerklizePositionValue)
	c.SetIndexDataInts(big.NewInt(999), big.NewInt(888))
	c.SetValueDataInts(big.NewInt(777), big.NewInt(666))

	out := TestDataSigV2{
		Desc: "Test claim merklize flag",
		In: ClaimMerklizeIn{
			Claim: c,
		},
		Out: ClaimMerklizeOut{
			Out:  big.NewInt(777),
			Flag: big.NewInt(1),
		},
	}

	json, err := json.Marshal(out)
	require.NoError(t, err)
	t.Log(string(json))
}
