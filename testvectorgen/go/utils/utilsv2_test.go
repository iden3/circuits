package utils

import (
	json2 "encoding/json"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/stretchr/testify/require"
)

const userPK = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"

func Test_IdentityData(t *testing.T) {

	id, err := NewIdentity(userPK)
	require.NoError(t, err)

	state, err := id.State()
	require.NoError(t, err)

	mtp, err := id.AuthMTPStrign()

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
		IssuerAuthClaimMtp:       mtp,
		IssuerAuthClaimsTreeRoot: id.Clt.Root().BigInt(),
		IssuerAuthRevTreeRoot:    id.Ret.Root().BigInt(),
		IssuerAuthRootsTreeRoot:  id.Rot.Root().BigInt(),
		IssuerAuthState:          state,
	}

	json, err := json2.Marshal(r)
	t.Log(string(json))

	t.Log("ID:", id.ID.String())
	t.Log("ID int:", id.ID.BigInt().String())
	did, err := core.ParseDIDFromID(id.ID)
	require.NoError(t, err)

	t.Log("DID:", did.String())
}
