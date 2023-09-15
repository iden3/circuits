package v3

import (
	"context"
	json2 "encoding/json"
	"math/big"
	"testing"

	"test/utils"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/stretchr/testify/require"
)

const (
	userPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	issuerPK  = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
)

var requestID = big.NewInt(41)

type Inputs struct {
	RequestID string `json:"requestID"`

	// user data
	UserGenesisID               string      `json:"userGenesisID"`            //
	ProfileNonce                string      `json:"profileNonce"`             //
	ClaimSubjectProfileNonce    string      `json:"claimSubjectProfileNonce"` //
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
	UserClaimsTreeRoot          string      `json:"userClaimsTreeRoot"`
	UserRevTreeRoot             string      `json:"userRevTreeRoot"`
	UserRootsTreeRoot           string      `json:"userRootsTreeRoot"`
	UserState                   string      `json:"userState"`
	GistRoot                    string      `json:"gistRoot"`
	GistMtp                     []string    `json:"gistMtp"`
	GistMtpAuxHi                string      `json:"gistMtpAuxHi"`
	GistMtpAuxHv                string      `json:"gistMtpAuxHv"`
	GistMtpNoAux                string      `json:"gistMtpNoAux"`

	IssuerID string `json:"issuerID"`
	// Claim
	IssuerClaim *core.Claim `json:"issuerClaim"`
	// Inclusion
	IssuerClaimMtp            []string         `json:"issuerClaimMtp"`
	IssuerClaimClaimsTreeRoot *merkletree.Hash `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimRevTreeRoot    *merkletree.Hash `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot  *merkletree.Hash `json:"issuerClaimRootsTreeRoot"`
	IssuerClaimIdenState      string           `json:"issuerClaimIdenState"`

	IsRevocationChecked             int              `json:"isRevocationChecked"`
	IssuerClaimNonRevClaimsTreeRoot *merkletree.Hash `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    *merkletree.Hash `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  *merkletree.Hash `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          string           `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []string         `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       string           `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       string           `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string           `json:"issuerClaimNonRevMtpNoAux"`

	ClaimSchema string `json:"claimSchema"`

	// Query
	// JSON path
	ClaimPathNotExists string   `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	ClaimPathMtp       []string `json:"claimPathMtp"`
	ClaimPathMtpNoAux  string   `json:"claimPathMtpNoAux"` // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi  string   `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv  string   `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathKey       string   `json:"claimPathKey"`      // hash of path in merklized json-ld document
	ClaimPathValue     string   `json:"claimPathValue"`    // value in this path in merklized json-ld document

	Operator  int      `json:"operator"`
	SlotIndex int      `json:"slotIndex"`
	Timestamp string   `json:"timestamp"`
	Value     []string `json:"value"`

	// additional sig inputs
	IssuerClaimSignatureR8X       string      `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y       string      `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS         string      `json:"issuerClaimSignatureS"`
	IssuerAuthClaim               *core.Claim `json:"issuerAuthClaim"`
	IssuerAuthClaimMtp            []string    `json:"issuerAuthClaimMtp"`
	IssuerAuthClaimNonRevMtp      []string    `json:"issuerAuthClaimNonRevMtp"`
	IssuerAuthClaimNonRevMtpAuxHi string      `json:"issuerAuthClaimNonRevMtpAuxHi"`
	IssuerAuthClaimNonRevMtpAuxHv string      `json:"issuerAuthClaimNonRevMtpAuxHv"`
	IssuerAuthClaimNonRevMtpNoAux string      `json:"issuerAuthClaimNonRevMtpNoAux"`
	IssuerAuthClaimsTreeRoot      string      `json:"issuerAuthClaimsTreeRoot"`
	IssuerAuthRevTreeRoot         string      `json:"issuerAuthRevTreeRoot"`
	IssuerAuthRootsTreeRoot       string      `json:"issuerAuthRootsTreeRoot"`

	ProofType string `json:"proofType"` // 0 for sig, 1 for mtp
	// Private random nonce, used to generate LinkID
	LinkNonce string `json:"linkNonce"`
}

type Outputs struct {
	ProofType              string `json:"proofType"` // 0 for sig, 1 for mtp
	Merklized              string `json:"merklized"`
	UserID                 string `json:"userID"`
	СircuitQueryHash       string `json:"circuitQueryHash"`
	RequestID              string `json:"requestID"`
	IssuerID               string `json:"issuerID"`
	IssuerClaimNonRevState string `json:"issuerClaimNonRevState"`
	Timestamp              string `json:"timestamp"`
	IsRevocationChecked    string `json:"isRevocationChecked"`
	Challenge              string `json:"challenge"`
	GistRoot               string `json:"gistRoot"`
	IssuerClaimIdenState   string `json:"issuerClaimIdenState"`
	LinkID                 string `json:"linkID"`
	// Sig specific
	IssuerAuthState string `json:"issuerAuthState"`
}

type TestData struct {
	Desc string  `json:"desc"`
	In   Inputs  `json:"inputs"`
	Out  Outputs `json:"expOut"`
}

func Test_ClaimIssuedOnUserID(t *testing.T) {
	desc := "User == Subject. Claim issued on UserID"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "claimIssuedOnUserID")
}

func Test_ClaimIssuedOnUserProfileID(t *testing.T) {
	desc := "User != Subject. Claim issued on ProfileID"
	isUserIDProfile := false
	isSubjectIDProfile := true

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "claimIssuedOnProfileID")
}

func Test_ClaimIssuedOnUserProfileID2(t *testing.T) {
	desc := "User == Subject. Claim issued on ProfileID"
	isUserIDProfile := true
	isSubjectIDProfile := true

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "claimIssuedOnProfileID2")
}

func Test_ClaimNonMerklized(t *testing.T) {
	desc := "User == Subject. Claim non merklized claim"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "claimNonMerklized")
}

func Test_RevokedClaimWithRevocationCheck(t *testing.T) {
	desc := "User's claim revoked and the circuit checking for revocation status (expected to fail)"
	fileName := "revoked_claim_with_revocation_check"

	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)

	nonceSubject := big.NewInt(0)

	claim := utils.DefaultUserClaim(t, user.ID)
	issuer.AddClaim(t, claim)

	revNonce := claim.GetRevocationNonce()
	revNonceBigInt := new(big.Int).SetUint64(revNonce)
	issuer.Ret.Add(context.Background(), revNonceBigInt, big.NewInt(0))

	issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	challenge := big.NewInt(12345)

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), utils.GistLevels)
	require.Nil(t, err)
	err = gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
	require.NoError(t, err)
	// user
	authMTProof := user.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := user.ClaimRevMTP(t, user.AuthClaim)

	sig := user.Sign(challenge)

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	require.NoError(t, err)

	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw, utils.GistLevels)

	inputs := Inputs{
		RequestID:     requestID.String(),
		UserGenesisID: user.ID.BigInt().String(),
		ProfileNonce:  nonce.String(),

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

		ClaimSubjectProfileNonce:        nonceSubject.String(),
		IssuerID:                        issuer.ID.BigInt().String(),
		IssuerClaim:                     claim,
		IssuerClaimMtp:                  issuerClaimMtp,
		IssuerClaimClaimsTreeRoot:       issuer.Clt.Root(),
		IssuerClaimRevTreeRoot:          issuer.Ret.Root(),
		IssuerClaimRootsTreeRoot:        issuer.Rot.Root(),
		IssuerClaimIdenState:            issuer.State(t).String(),
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root(),
		IssuerClaimNonRevState:          issuer.State(t).String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		ClaimSchema:                     "180410020913331409885634153623124536270",
		ClaimPathNotExists:              "0", // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:                    utils.PrepareStrArray([]string{}, 32),
		ClaimPathMtpNoAux:               "0",
		ClaimPathMtpAuxHi:               "0",
		ClaimPathMtpAuxHv:               "0",
		ClaimPathKey:                    "0",
		ClaimPathValue:                  "0",
		IsRevocationChecked:             1,
		Operator:                        utils.EQ,
		SlotIndex:                       2,
		Timestamp:                       timestamp,
		Value:                           utils.PrepareStrArray([]string{"10"}, 64),

		IssuerClaimSignatureR8X:       "0",
		IssuerClaimSignatureR8Y:       "0",
		IssuerClaimSignatureS:         "0",
		IssuerAuthClaim:               &core.Claim{},
		IssuerAuthClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerAuthClaimNonRevMtp:      utils.PrepareStrArray([]string{}, 40),
		IssuerAuthClaimNonRevMtpAuxHi: "0",
		IssuerAuthClaimNonRevMtpAuxHv: "0",
		IssuerAuthClaimNonRevMtpNoAux: "0",
		IssuerAuthClaimsTreeRoot:      "0",
		IssuerAuthRevTreeRoot:         "0",
		IssuerAuthRootsTreeRoot:       "0",

		LinkNonce: "0",

		ProofType: "1",
	}

	valuesHash, err := utils.PoseidonHashValue(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)
	claimSchemaInt, ok := big.NewInt(0).SetString(inputs.ClaimSchema, 10)
	require.True(t, ok)
	circuitQueryHash, err := poseidon.Hash([]*big.Int{
		claimSchemaInt,
		big.NewInt(int64(inputs.SlotIndex)),
		big.NewInt(int64(inputs.Operator)),
		big.NewInt(0),
		big.NewInt(0),
		valuesHash,
	})
	require.NoError(t, err)
	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 user.ID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		СircuitQueryHash:       circuitQueryHash.String(),
		Timestamp:              timestamp,
		Merklized:              "0",
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
		IsRevocationChecked:    "1",
		ProofType:              "1",
		IssuerAuthState:        "0",
		LinkID:                 "0",
	}

	json, err := json2.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func Test_RevokedClaimWithoutRevocationCheck(t *testing.T) {
	desc := "User's claim revoked and the circuit not checking for revocation status (expected to fail)"
	fileName := "revoked_claim_without_revocation_check"

	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)

	nonceSubject := big.NewInt(0)

	claim := utils.DefaultUserClaim(t, user.ID)
	issuer.AddClaim(t, claim)

	revNonce := claim.GetRevocationNonce()
	revNonceBigInt := new(big.Int).SetUint64(revNonce)
	issuer.Ret.Add(context.Background(), revNonceBigInt, big.NewInt(0))

	issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	challenge := big.NewInt(12345)

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 64)
	require.Nil(t, err)
	err = gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
	require.NoError(t, err)
	// user
	authMTProof := user.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := user.ClaimRevMTP(t, user.AuthClaim)

	sig := user.Sign(challenge)

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	require.NoError(t, err)

	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw, utils.GistLevels)

	inputs := Inputs{
		RequestID:     requestID.String(),
		UserGenesisID: user.ID.BigInt().String(),
		ProfileNonce:  nonce.String(),

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

		ClaimSubjectProfileNonce:        nonceSubject.String(),
		IssuerID:                        issuer.ID.BigInt().String(),
		IssuerClaim:                     claim,
		IssuerClaimMtp:                  issuerClaimMtp,
		IssuerClaimClaimsTreeRoot:       issuer.Clt.Root(),
		IssuerClaimRevTreeRoot:          issuer.Ret.Root(),
		IssuerClaimRootsTreeRoot:        issuer.Rot.Root(),
		IssuerClaimIdenState:            issuer.State(t).String(),
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root(),
		IssuerClaimNonRevState:          issuer.State(t).String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		ClaimSchema:                     "180410020913331409885634153623124536270",
		ClaimPathNotExists:              "0", // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:                    utils.PrepareStrArray([]string{}, 32),
		ClaimPathMtpNoAux:               "0",
		ClaimPathMtpAuxHi:               "0",
		ClaimPathMtpAuxHv:               "0",
		ClaimPathKey:                    "0",
		ClaimPathValue:                  "0",
		IsRevocationChecked:             0,
		Operator:                        utils.EQ,
		SlotIndex:                       2,
		Timestamp:                       timestamp,
		Value:                           utils.PrepareStrArray([]string{"10"}, 64),

		IssuerClaimSignatureR8X:       "0",
		IssuerClaimSignatureR8Y:       "0",
		IssuerClaimSignatureS:         "0",
		IssuerAuthClaim:               &core.Claim{},
		IssuerAuthClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerAuthClaimNonRevMtp:      utils.PrepareStrArray([]string{}, 40),
		IssuerAuthClaimNonRevMtpAuxHi: "0",
		IssuerAuthClaimNonRevMtpAuxHv: "0",
		IssuerAuthClaimNonRevMtpNoAux: "0",
		IssuerAuthClaimsTreeRoot:      "0",
		IssuerAuthRevTreeRoot:         "0",
		IssuerAuthRootsTreeRoot:       "0",

		LinkNonce: "0",

		ProofType: "1",
	}

	valuesHash, err := utils.PoseidonHashValue(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)
	claimSchemaInt, ok := big.NewInt(0).SetString(inputs.ClaimSchema, 10)
	require.True(t, ok)
	circuitQueryHash, err := poseidon.Hash([]*big.Int{
		claimSchemaInt,
		big.NewInt(int64(inputs.SlotIndex)),
		big.NewInt(int64(inputs.Operator)),
		big.NewInt(0),
		big.NewInt(0),
		valuesHash,
	})

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 user.ID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		СircuitQueryHash:       circuitQueryHash.String(),
		Timestamp:              timestamp,
		Merklized:              "0",
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
		IsRevocationChecked:    "0",
		ProofType:              "1",
		IssuerAuthState:        "0",
		LinkID:                 "0",
	}

	json, err := json2.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func generateJSONLDTestData(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool, fileName string) {
	var err error

	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)
	if isUserIDProfile {
		nonce = big.NewInt(10)
		userProfileID, err = core.ProfileID(user.ID, nonce)
		require.NoError(t, err)
	}

	subjectID := user.ID
	nonceSubject := big.NewInt(0)
	if isSubjectIDProfile {
		nonceSubject = big.NewInt(999)
		subjectID, err = core.ProfileID(user.ID, nonceSubject)
		require.NoError(t, err)
	}

	mz, claim := utils.DefaultJSONUserClaim(t, subjectID)

	path, err := merklize.NewPath(
		"https://www.w3.org/2018/credentials#credentialSubject",
		"https://w3id.org/citizenship#residentSince")
	require.NoError(t, err)

	jsonP, value, err := mz.Proof(context.Background(), path)
	require.NoError(t, err)

	valueKey, err := value.MtEntry()
	require.NoError(t, err)

	claimJSONLDProof, claimJSONLDProofAux := utils.PrepareProof(jsonP, utils.ClaimLevels)

	pathKey, err := path.MtEntry()
	require.NoError(t, err)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	challenge := big.NewInt(12345)

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 64)
	require.Nil(t, err)
	err = gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
	require.NoError(t, err)
	// user
	authMTProof := user.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := user.ClaimRevMTP(t, user.AuthClaim)

	sig := user.Sign(challenge)

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	require.NoError(t, err)

	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw, utils.GistLevels)

	inputs := Inputs{
		RequestID:     requestID.String(),
		UserGenesisID: user.ID.BigInt().String(),
		ProfileNonce:  nonce.String(),

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

		ClaimSubjectProfileNonce:        nonceSubject.String(),
		IssuerID:                        issuer.ID.BigInt().String(),
		IssuerClaim:                     claim,
		IssuerClaimMtp:                  issuerClaimMtp,
		IssuerClaimClaimsTreeRoot:       issuer.Clt.Root(),
		IssuerClaimRevTreeRoot:          issuer.Ret.Root(),
		IssuerClaimRootsTreeRoot:        issuer.Rot.Root(),
		IssuerClaimIdenState:            issuer.State(t).String(),
		IsRevocationChecked:             1,
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root(),
		IssuerClaimNonRevState:          issuer.State(t).String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		ClaimSchema:                     "180410020913331409885634153623124536270",
		ClaimPathNotExists:              "0", // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:                    claimJSONLDProof,
		ClaimPathMtpNoAux:               claimJSONLDProofAux.NoAux,
		ClaimPathMtpAuxHi:               claimJSONLDProofAux.Key,
		ClaimPathMtpAuxHv:               claimJSONLDProofAux.Value,
		ClaimPathKey:                    pathKey.String(),
		ClaimPathValue:                  valueKey.String(),
		Operator:                        utils.EQ,
		SlotIndex:                       0,
		Timestamp:                       timestamp,
		Value:                           utils.PrepareStrArray([]string{valueKey.String()}, 64),

		IssuerClaimSignatureR8X:       "0",
		IssuerClaimSignatureR8Y:       "0",
		IssuerClaimSignatureS:         "0",
		IssuerAuthClaim:               &core.Claim{},
		IssuerAuthClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerAuthClaimNonRevMtp:      utils.PrepareStrArray([]string{}, 40),
		IssuerAuthClaimNonRevMtpAuxHi: "0",
		IssuerAuthClaimNonRevMtpAuxHv: "0",
		IssuerAuthClaimNonRevMtpNoAux: "0",
		IssuerAuthClaimsTreeRoot:      "0",
		IssuerAuthRevTreeRoot:         "0",
		IssuerAuthRootsTreeRoot:       "0",

		LinkNonce: "0",

		ProofType: "1",
	}
	valuesHash, err := utils.PoseidonHashValue(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)
	claimSchemaInt, ok := big.NewInt(0).SetString(inputs.ClaimSchema, 10)
	require.True(t, ok)
	circuitQueryHash, err := poseidon.Hash([]*big.Int{
		claimSchemaInt,
		big.NewInt(int64(inputs.SlotIndex)),
		big.NewInt(int64(inputs.Operator)),
		pathKey,
		big.NewInt(0),
		valuesHash,
	})
	require.NoError(t, err)

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		СircuitQueryHash:       circuitQueryHash.String(),
		Timestamp:              timestamp,
		Merklized:              "1",
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
		IsRevocationChecked:    "1",
		ProofType:              "1",
		IssuerAuthState:        "0",
		LinkID:                 "0",
	}

	json, err := json2.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))

}

func generateTestData(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool, fileName string) {
	var err error

	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)
	if isUserIDProfile {
		nonce = big.NewInt(10)
		userProfileID, err = core.ProfileID(user.ID, nonce)
		require.NoError(t, err)
	}

	subjectID := user.ID
	nonceSubject := big.NewInt(0)
	if isSubjectIDProfile {
		nonceSubject = big.NewInt(999)
		subjectID, err = core.ProfileID(user.ID, nonceSubject)
		require.NoError(t, err)
	}

	claim := utils.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)
	require.NoError(t, err)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	challenge := big.NewInt(12345)

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 64)
	require.Nil(t, err)
	err = gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
	require.NoError(t, err)
	// user
	authMTProof := user.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := user.ClaimRevMTP(t, user.AuthClaim)

	sig := user.Sign(challenge)

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	require.NoError(t, err)

	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw, utils.GistLevels)

	inputs := Inputs{
		RequestID:     requestID.String(),
		UserGenesisID: user.ID.BigInt().String(),
		ProfileNonce:  nonce.String(),

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

		ClaimSubjectProfileNonce:        nonceSubject.String(),
		IssuerID:                        issuer.ID.BigInt().String(),
		IssuerClaim:                     claim,
		IssuerClaimMtp:                  issuerClaimMtp,
		IssuerClaimClaimsTreeRoot:       issuer.Clt.Root(),
		IssuerClaimRevTreeRoot:          issuer.Ret.Root(),
		IssuerClaimRootsTreeRoot:        issuer.Rot.Root(),
		IssuerClaimIdenState:            issuer.State(t).String(),
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root(),
		IssuerClaimNonRevState:          issuer.State(t).String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		ClaimSchema:                     "180410020913331409885634153623124536270",
		ClaimPathNotExists:              "0", // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:                    utils.PrepareStrArray([]string{}, 32),
		ClaimPathMtpNoAux:               "0",
		ClaimPathMtpAuxHi:               "0",
		ClaimPathMtpAuxHv:               "0",
		ClaimPathKey:                    "0",
		ClaimPathValue:                  "0",
		IsRevocationChecked:             1,
		Operator:                        utils.EQ,
		SlotIndex:                       2,
		Timestamp:                       timestamp,
		Value:                           utils.PrepareStrArray([]string{"10"}, 64),

		IssuerClaimSignatureR8X:       "0",
		IssuerClaimSignatureR8Y:       "0",
		IssuerClaimSignatureS:         "0",
		IssuerAuthClaim:               &core.Claim{},
		IssuerAuthClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerAuthClaimNonRevMtp:      utils.PrepareStrArray([]string{}, 40),
		IssuerAuthClaimNonRevMtpAuxHi: "0",
		IssuerAuthClaimNonRevMtpAuxHv: "0",
		IssuerAuthClaimNonRevMtpNoAux: "0",
		IssuerAuthClaimsTreeRoot:      "0",
		IssuerAuthRevTreeRoot:         "0",
		IssuerAuthRootsTreeRoot:       "0",

		LinkNonce: "0",

		ProofType: "1",
	}

	valuesHash, err := utils.PoseidonHashValue(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)
	claimSchemaInt, ok := big.NewInt(0).SetString(inputs.ClaimSchema, 10)
	require.True(t, ok)
	circuitQueryHash, err := poseidon.Hash([]*big.Int{
		claimSchemaInt,
		big.NewInt(int64(inputs.SlotIndex)),
		big.NewInt(int64(inputs.Operator)),
		big.NewInt(0),
		big.NewInt(0),
		valuesHash,
	})
	require.NoError(t, err)

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		СircuitQueryHash:       circuitQueryHash.String(),
		Timestamp:              timestamp,
		Merklized:              "0",
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(), // 0 for inclusion, 1 for non-inclusion
		IsRevocationChecked:    "1",
		ProofType:              "1",
		IssuerAuthState:        "0",
		LinkID:                 "0",
	}

	json, err := json2.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
