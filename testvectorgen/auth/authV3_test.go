package main

import (
	"context"
	"encoding/hex"
	json2 "encoding/json"
	"fmt"
	"math/big"
	"testing"

	"test/utils"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/stretchr/testify/require"
)

const (
	userPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	userPK2   = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
)

type AuthV3Inputs struct {
	UserGenesisID               string      `json:"genesisID"`
	Nonce                       string      `json:"profileNonce"`
	UserAuthClaim               *core.Claim `json:"authClaim"`
	UserAuthClaimMtp            []string    `json:"authClaimIncMtp"`
	UserAuthClaimNonRevMtp      []string    `json:"authClaimNonRevMtp"`
	UserAuthClaimNonRevMtpAuxHi string      `json:"authClaimNonRevMtpAuxHi"`
	UserAuthClaimNonRevMtpAuxHv string      `json:"authClaimNonRevMtpAuxHv"`
	UserAuthClaimNonRevMtpNoAux string      `json:"authClaimNonRevMtpNoAux"`
	Challenge                   string      `json:"challenge"`
	ChallengeSignatureR8X       string      `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y       string      `json:"challengeSignatureR8y"`
	ChallengeSignatureS         string      `json:"challengeSignatureS"`
	UserClaimsTreeRoot          string      `json:"claimsTreeRoot"`
	UserRevTreeRoot             string      `json:"revTreeRoot"`
	UserRootsTreeRoot           string      `json:"rootsTreeRoot"`
	UserState                   string      `json:"state"`
	GistRoot                    string      `json:"gistRoot"`
	GistMtp                     []string    `json:"gistMtp"`
	GistMtpAuxHi                string      `json:"gistMtpAuxHi"`
	GistMtpAuxHv                string      `json:"gistMtpAuxHv"`
	GistMtpNoAux                string      `json:"gistMtpNoAux"`
}

type AuthV3Outputs struct {
	ID        string `json:"userID"`
	GistRoot  string `json:"gistRoot"`
	Challenge string `json:"challenge"`
}

type TestDataAuthV3 struct {
	Desc string        `json:"desc"`
	In   AuthV3Inputs  `json:"inputs"`
	Out  AuthV3Outputs `json:"expOut"`
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

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 40)
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
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw, utils.GistLevels)

	inputs := AuthV3Inputs{
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

	out := AuthV3Outputs{
		ID:        userProfile.BigInt().String(),
		Challenge: challenge.String(),
		GistRoot:  gistRoot.BigInt().String(),
	}

	json, err := json2.Marshal(TestDataAuthV3{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func TestTre(t *testing.T) {

	tree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 40)
	require.Nil(t, err)

	X, ok := new(big.Int).SetString("17640206035128972995519606214765283372613874593503528180869261482403155458945", 10)
	require.True(t, ok)

	Y, ok := new(big.Int).SetString("20634138280259599560273310290025659992320584624461316485434108770067472477956", 10)
	require.True(t, ok)

	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("ca938857241db9451ea329256b9c06e5") // V1
	//schemaEncodedBytes, _ := hex.DecodeString("013fd3f623559d850fb5b02ff012d0e2") // V2
	copy(schemaHash[:], schemaEncodedBytes)

	// NOTE: We take nonce as hash of public key to make it random
	// We don't use random number here because this test vectors will be used for tests
	// and have randomization inside tests is usually a bad idea
	revNonce := uint64(15930428023331155902)
	require.NoError(t, err)

	claim, err := core.NewClaim(schemaHash,
		core.WithIndexDataInts(X, Y),
		core.WithRevocationNonce(revNonce))
	require.NoError(t, err)

	marshal, err := json2.Marshal(claim)
	require.NoError(t, err)
	fmt.Println(string(marshal))

	hi, hv, err := claim.HiHv()
	require.NoError(t, err)

	fmt.Println("hi", hi)
	fmt.Println("hv", hv)

	err = tree.Add(context.Background(), hi, hv)
	require.NoError(t, err)

	fmt.Println("root", tree.Root().BigInt())

	clr, _ := new(big.Int).SetString("9763429684850732628215303952870004997159843236039795272605841029866455670219", 10)
	state, err := core.IdenState(clr, big.NewInt(0), big.NewInt(0))
	require.NoError(t, err)

	typ, err := core.BuildDIDType(core.DIDMethodIden3, core.Polygon, core.Mumbai)
	require.NoError(t, err)
	id, err := core.NewIDFromIdenState(typ, state)
	require.NoError(t, err)

	fmt.Println("id", id.BigInt())
	fmt.Println("id", id.String())

	did, err := core.ParseDIDFromID(*id)
	require.NoError(t, err)
	fmt.Println("did", did.String())

	//{“schema":"ca938857241db9451ea329256b9c06e5",
	//"nonce":"15930428023331155902"," +
	//"indexSlotA":"17640206035128972995519606214765283372613874593503528180869261482403155458945",
	// "indexSlotB":"20634138280259599560273310290025659992320584624461316485434108770067472477956"}
}
