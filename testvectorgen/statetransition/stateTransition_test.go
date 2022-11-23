package main

import (
	json2 "encoding/json"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
	"test/utils"
)

const (
	userPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	userPK2   = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
)

type StateTransitionInputs struct {
	AuthClaim               *core.Claim `json:"authClaim"`
	AuthClaimMtp            []string    `json:"authClaimMtp"`
	AuthClaimNonRevMtp      []string    `json:"authClaimNonRevMtp"`
	AuthClaimNonRevMtpAuxHi string      `json:"authClaimNonRevMtpAuxHi"`
	AuthClaimNonRevMtpAuxHv string      `json:"authClaimNonRevMtpAuxHv"`
	AuthClaimNonRevMtpNoAux string      `json:"authClaimNonRevMtpNoAux"`
	ClaimsTreeRoot          string      `json:"claimsTreeRoot"`
	IsOldStateGenesis       string      `json:"isOldStateGenesis"`
	NewUserState            string      `json:"newUserState"`
	OldUserState            string      `json:"oldUserState"`
	RevTreeRoot             string      `json:"revTreeRoot"`
	RootsTreeRoot           string      `json:"rootsTreeRoot"`
	SignatureR8X            string      `json:"signatureR8x"`
	SignatureR8Y            string      `json:"signatureR8y"`
	SignatureS              string      `json:"signatureS"`
	UserID                  string      `json:"userID"`
}

type StateTransitionOutputs struct {
	ID                string `json:"userID"`
	NewUserState      string `json:"newUserState"`
	OldUserState      string `json:"oldUserState"`
	IsOldStateGenesis string `json:"isOldStateGenesis"`
}

type TestDataStateTransition struct {
	Desc string                 `json:"desc"`
	In   StateTransitionInputs  `json:"inputs"`
	Out  StateTransitionOutputs `json:"expOut"`
}

func Test_GenesisState(t *testing.T) {

	desc := "Positive: old state is genesis"
	isUserStateGenesis := false

	generateAuthTestData(t, isUserStateGenesis, desc, "genesis_state")
}

func Test_NotGenesis(t *testing.T) {

	desc := "Positive: old state is not genesis"
	isUserStateGenesis := true

	generateAuthTestData(t, isUserStateGenesis, desc, "not_genesis_state")
}

func generateAuthTestData(t *testing.T, genesis bool, desc, fileName string) {

	user := utils.NewIdentity(t, userPK)

	isGenesis := "1"

	// user
	authMTProof := user.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := user.ClaimRevMTP(t, user.AuthClaim)

	oldState := user.State(t) // old state is genesis
	oldCltRoot := user.Clt.Root().BigInt().String()
	oldRevRoot := user.Ret.Root().BigInt().String()
	oldRotRoot := user.Rot.Root().BigInt().String()

	//if genesis == false {
	// extract pubKey
	authClaim2, _, err := utils.NewAuthClaim(userPK2)
	require.NoError(t, err)

	user.AddClaim(t, authClaim2)

	if genesis {
		isGenesis = "0"

		oldState = user.State(t) // old state is genesis
		oldCltRoot = user.Clt.Root().BigInt().String()
		oldRevRoot = user.Ret.Root().BigInt().String()
		oldRotRoot = user.Rot.Root().BigInt().String()
		authMTProof = user.AuthMTPStrign(t)

		authNonRevMTProof, nodeAuxNonRev = user.ClaimRevMTP(t, user.AuthClaim)
		require.NoError(t, err)

		claim1 := utils.DefaultUserClaim(t, user.ID)

		user.AddClaim(t, claim1)
	}

	hashOldAndNewStates, err := poseidon.Hash(
		[]*big.Int{oldState, user.State(t)})
	require.NoError(t, err)

	sig := user.Sign(hashOldAndNewStates)
	require.NoError(t, err)

	inputs := StateTransitionInputs{
		AuthClaim:               user.AuthClaim,
		AuthClaimMtp:            authMTProof,
		AuthClaimNonRevMtp:      authNonRevMTProof,
		AuthClaimNonRevMtpAuxHi: nodeAuxNonRev.Key,
		AuthClaimNonRevMtpAuxHv: nodeAuxNonRev.Value,
		AuthClaimNonRevMtpNoAux: nodeAuxNonRev.NoAux,
		ClaimsTreeRoot:          oldCltRoot,
		RevTreeRoot:             oldRevRoot,
		RootsTreeRoot:           oldRotRoot,
		IsOldStateGenesis:       isGenesis,
		NewUserState:            user.State(t).String(),
		OldUserState:            oldState.String(),
		SignatureR8X:            sig.R8.X.String(),
		SignatureR8Y:            sig.R8.Y.String(),
		SignatureS:              sig.S.String(),
		UserID:                  user.ID.BigInt().String(),
	}

	out := StateTransitionOutputs{
		ID:                user.ID.BigInt().String(),
		NewUserState:      user.State(t).String(),
		OldUserState:      oldState.String(),
		IsOldStateGenesis: isGenesis,
	}

	json, err := json2.Marshal(TestDataStateTransition{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
