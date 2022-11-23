package main

import (
	"context"
	json2 "encoding/json"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/stretchr/testify/require"
	"test/utils"
)

const (
	userPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	userPK2   = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
)

type AuthV2Inputs struct {
	UserGenesisID               string      `json:"userGenesisID"`
	Nonce                       string      `json:"nonce"`
	UserAuthClaim               *core.Claim `json:"userAuthClaim"`
	UserAuthClaimMtp            []string    `json:"userAuthClaimMtp"`
	UserAuthClaimNonRevMtp      []string    `json:"userAuthClaimNonRevMtp"`
	UserAuthClaimNonRevMtpAuxHi string      `json:"userAuthClaimNonRevMtpAuxHi"`
	UserAuthClaimNonRevMtpAuxHv string      `json:"userAuthClaimNonRevMtpAuxHv"`
	UserAuthClaimNonRevMtpNoAux string      `json:"userAuthClaimNonRevMtpNoAux"`
	Challenge                   string      `json:"challenge"`
	ChallengeSignatureR8X       string      `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y       string      `json:"challengeSignatureR8y"`
	ChallengeSignatureS         string      `json:"challengeSignatureS"`
	UserClaimsTreeRoot          string      `json:"userClaimsTreeRoot"`
	UserRevTreeRoot             string      `json:"userRevTreeRoot"`
	UserRootsTreeRoot           string      `json:"userRootsTreeRoot"`
	UserState                   string      `json:"userState"`
	GistRoot                    string      `json:"gistRoot"`
	GistMtp                     []string    `json:"gistMtp"`
	GistMtpAuxHi                string      `json:"gistMtpAuxHi"`
	GistMtpAuxHv                string      `json:"gistMtpAuxHv"`
	GistMtpNoAux                string      `json:"gistMtpNoAux"`
}

type AuthV2Outputs struct {
	ID        string `json:"userID"`
	GistRoot  string `json:"gistRoot"`
	Challenge string `json:"challenge"`
}

type TestDataAuthV2 struct {
	Desc string        `json:"desc"`
	In   AuthV2Inputs  `json:"inputs"`
	Out  AuthV2Outputs `json:"expOut"`
}

func Test_UserID_Subject(t *testing.T) {

	desc := "Ownership true. User state: genesis. Auth claims total/signedWith/revoked: 1/1/none"
	isUserIDProfile := false
	isSecondAuthClaim := false
	isUserStateGenesis := true

	generateAuthTestData(t, isUserIDProfile, isUserStateGenesis, isSecondAuthClaim, desc, "userID_genesis")
}

func TestNotGenesisUserSate(t *testing.T) {

	desc := "Ownership true. User state: not-genesis. Auth claims total/signedWith/revoked: 1/1/none"
	isUserIDProfile := false

	isUserStateGenesis := false
	isSecondAuthClaim := false

	generateAuthTestData(t, isUserIDProfile, isUserStateGenesis, isSecondAuthClaim, desc, "user_state_not_genesis")
}

func TestNotGenesisUserSateWithRevokedClaims(t *testing.T) {
	desc := "Ownership true. User state: not-genesis. Auth claims total/signedWith/revoked: 1/1/none"
	isUserIDProfile := false
	isUserStateGenesis := false
	isSecondAuthClaim := true
	generateAuthTestData(t, isUserIDProfile, isUserStateGenesis, isSecondAuthClaim, desc,
		"user_state_not_genesis_second_auth_claim")
}

func Test_ProfileID(t *testing.T) {

	desc := "nonce=10. ProfileID == UserID should be true. Ownership true. User state: genesis. Auth claims total/signedWith/revoked: 1/1/none"
	isUserIDProfile := true
	isSecondAuthClaim := false
	isUserStateGenesis := true

	generateAuthTestData(t, isUserIDProfile, isUserStateGenesis, isSecondAuthClaim, desc, "userID_profileID")
}

func generateAuthTestData(t *testing.T, profile, genesis, isSecondAuthClaim bool, desc, fileName string) {

	nonce := big.NewInt(0)

	challenge := big.NewInt(12345)

	user := utils.NewIdentity(t, userPK)

	var err error

	userProfile := user.ID
	if profile {
		nonce = big.NewInt(10)
		userProfile, err = core.ProfileID(user.ID, nonce)
		require.NoError(t, err)
	}

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	require.Nil(t, err)
	gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))

	if genesis == false {
		// extract pubKey
		authClaim2, pk2 := utils.NewAuthClaim(t, userPK2)

		user.AddClaim(t, authClaim2)

		if isSecondAuthClaim {

			// revoke auth claim
			revNonce := user.AuthClaim.GetRevocationNonce()
			err = user.Ret.Add(context.Background(), new(big.Int).SetUint64(revNonce), big.NewInt(0))
			require.NoError(t, err)

			// set new auth claim
			user.AuthClaim = authClaim2
			user.PK = pk2

		}

		err = gisTree.Add(context.Background(), user.IDHash(t), user.State(t))
		require.NoError(t, err)

	}

	// user
	authMTProof := user.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := user.ClaimRevMTP(t, user.AuthClaim)

	sig := user.Sign(challenge)

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	require.NoError(t, err)

	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	inputs := AuthV2Inputs{
		UserGenesisID:               user.ID.BigInt().String(),
		Nonce:                       nonce.String(),
		UserAuthClaim:               user.AuthClaim,
		UserAuthClaimMtp:            authMTProof,
		UserAuthClaimNonRevMtp:      authNonRevMTProof,
		UserAuthClaimNonRevMtpAuxHi: nodeAuxNonRev.Key,
		UserAuthClaimNonRevMtpAuxHv: nodeAuxNonRev.Value,
		UserAuthClaimNonRevMtpNoAux: nodeAuxNonRev.NoAux,
		Challenge:                   challenge.String(),
		ChallengeSignatureR8X:       sig.R8.X.String(),
		ChallengeSignatureR8Y:       sig.R8.Y.String(),
		ChallengeSignatureS:         sig.S.String(),
		UserClaimsTreeRoot:          user.Clt.Root().BigInt().String(),
		UserRevTreeRoot:             user.Ret.Root().BigInt().String(),
		UserRootsTreeRoot:           user.Rot.Root().BigInt().String(),
		UserState:                   user.State(t).String(),
		GistRoot:                    gistRoot.BigInt().String(),
		GistMtp:                     gistProof,
		GistMtpAuxHi:                gistNodAux.Key,
		GistMtpAuxHv:                gistNodAux.Value,
		GistMtpNoAux:                gistNodAux.NoAux,
	}

	out := AuthV2Outputs{
		ID:        userProfile.BigInt().String(),
		Challenge: challenge.String(),
		GistRoot:  gistRoot.BigInt().String(),
	}

	json, err := json2.Marshal(TestDataAuthV2{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
