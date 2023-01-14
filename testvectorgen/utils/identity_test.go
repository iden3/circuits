package utils

import (
	json2 "encoding/json"
	"fmt"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/stretchr/testify/require"
)

const userPK = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"

func Test_IdentityData(t *testing.T) {

	id := NewIdentity(t, userPK)

	r := struct {
		IssuerID                 *big.Int    `json:"issuerID"`
		IssuerAuthClaim          *core.Claim `json:"issuerAuthClaim"`
		IssuerAuthClaimMtp       []string    `json:"issuerAuthClaimMtp"`
		IssuerAuthClaimsTreeRoot *big.Int    `json:"issuerAuthClaimsTreeRoot"`
		IssuerAuthRevTreeRoot    *big.Int    `json:"issuerAuthRevTreeRoot"`
		IssuerAuthRootsTreeRoot  *big.Int    `json:"issuerAuthRootsTreeRoot"`
		IssuerAuthState          *big.Int    `json:"issuerAuthState"`
	}{
		IssuerID:                 id.ID.BigInt(),
		IssuerAuthClaim:          id.AuthClaim,
		IssuerAuthClaimMtp:       id.AuthMTPStrign(t),
		IssuerAuthClaimsTreeRoot: id.Clt.Root().BigInt(),
		IssuerAuthRevTreeRoot:    id.Ret.Root().BigInt(),
		IssuerAuthRootsTreeRoot:  id.Rot.Root().BigInt(),
		IssuerAuthState:          id.State(t),
	}

	json, err := json2.Marshal(r)
	t.Log(string(json))

	t.Log("ID:", id.ID.String())
	t.Log("ID int:", id.ID.BigInt().String())
	did, err := core.ParseDIDFromID(id.ID)
	require.NoError(t, err)

	t.Log("DID:", did.String())
}

// const testCases = [
//             new Array(64).fill(0),
//             new Array(63).fill(0).map((_, i) => i + 1),
//             new Array(60).fill(0).map((_, i) => 60 - i),
//             new Array(5).fill(0).map((_, i) => i + 1),
//             [0],
//             new Array(6).fill(0).map((_, i) => i + 1),

//         ];

func Test_PoseidonValueHash(t *testing.T) {

	getBigintArray := func(l int, f func (idx int) int) []*big.Int  {
		result := make([]*big.Int, l)
		for i := 0; i < l; i++ {
			result[i] = big.NewInt(int64(f(i)))
		}
		return result
	}

	testCases := []struct {
		name string
		input []*big.Int
	}{
		{
			name: "PoseidonValueHash all zeros",
			input: getBigintArray(63, func(idx int) int {
				return idx +1
			}),
		},
		// {
		// 	name: "PoseidonValueHash 60 items",
		// 	input: getBigintArray(60, func(idx int) int {
		// 		return 60 - idx
		// 	}),
		// },
		// {
		// 	name: "PoseidonValueHash 63 idx + 1",
		// 	input: getBigintArray(63, func(idx int) int {
		// 		return idx + 1
		// 	}),
		// },
		// {
		// 	name: "PoseidonValueHash 5 idx + 1",
		// 	input: getBigintArray(5, func(idx int) int {
		// 		return idx + 1
		// 	}),
		// },
		// {
		// 	name: "PoseidonValueHash 1 item",
		// 	input: getBigintArray(1, func(idx int) int {
		// 		return 0	
		// 	}),
		// },
		// {
		// 	name: "PoseidonValueHash all zeros",
		// 	input: getBigintArray(64, func(idx int) int {
		// 		return 0
		// 	}),
		// },

	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			poseidonValueHash, err := PoseidonValueHash(tc.input)
			require.NoError(t, err)
			fmt.Println(tc.name, len(tc.input))
			fmt.Println("PoseidonValueHash:", poseidonValueHash.String())
		})
	}

}

