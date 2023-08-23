package v3

import (
	"context"
	"encoding/json"
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
	UserGenesisID            string `json:"userGenesisID"`
	ProfileNonce             string `json:"profileNonce"`
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"`

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
	IssuerClaim                     *core.Claim `json:"issuerClaim"`
	IssuerClaimNonRevClaimsTreeRoot string      `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    string      `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  string      `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          string      `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []string    `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       string      `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       string      `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string      `json:"issuerClaimNonRevMtpNoAux"`
	ClaimSchema                     string      `json:"claimSchema"`
	IssuerClaimSignatureR8X         string      `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y         string      `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS           string      `json:"issuerClaimSignatureS"`
	IssuerAuthClaim                 *core.Claim `json:"issuerAuthClaim"`
	IssuerAuthClaimMtp              []string    `json:"issuerAuthClaimMtp"`
	IssuerAuthClaimNonRevMtp        []string    `json:"issuerAuthClaimNonRevMtp"`
	IssuerAuthClaimNonRevMtpAuxHi   string      `json:"issuerAuthClaimNonRevMtpAuxHi"`
	IssuerAuthClaimNonRevMtpAuxHv   string      `json:"issuerAuthClaimNonRevMtpAuxHv"`
	IssuerAuthClaimNonRevMtpNoAux   string      `json:"issuerAuthClaimNonRevMtpNoAux"`
	IssuerAuthClaimsTreeRoot        string      `json:"issuerAuthClaimsTreeRoot"`
	IssuerAuthRevTreeRoot           string      `json:"issuerAuthRevTreeRoot"`
	IssuerAuthRootsTreeRoot         string      `json:"issuerAuthRootsTreeRoot"`
	// Query
	// JSON path
	ClaimPathNotExists string   `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	ClaimPathMtp       []string `json:"claimPathMtp"`
	ClaimPathMtpNoAux  string   `json:"claimPathMtpNoAux"` // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi  string   `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv  string   `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathKey       string   `json:"claimPathKey"`      // hash of path in merklized json-ld document
	ClaimPathValue     string   `json:"claimPathValue"`    // value in this path in merklized json-ld document

	Operator            int      `json:"operator"`
	SlotIndex           int      `json:"slotIndex"`
	Timestamp           string   `json:"timestamp"`
	IsRevocationChecked int      `json:"isRevocationChecked"`
	Value               []string `json:"value"`

	// additional mtp inputs`
	IssuerClaimMtp            []string `json:"issuerClaimMtp"`
	IssuerClaimClaimsTreeRoot string   `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimRevTreeRoot    string   `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot  string   `json:"issuerClaimRootsTreeRoot"`
	IssuerClaimIdenState      string   `json:"issuerClaimIdenState"`

	ProofType string `json:"proofType"`
}

type Outputs struct {
	ProofType              string `json:"proofType"`
	Merklized              string `json:"merklized"`
	UserID                 string `json:"userID"`
	СircuitQueryHash       string `json:"circuitQueryHash"`
	IssuerAuthState        string `json:"issuerAuthState"`
	RequestID              string `json:"requestID"`
	IssuerID               string `json:"issuerID"`
	IssuerClaimNonRevState string `json:"issuerClaimNonRevState"`
	Timestamp              string `json:"timestamp"`
	IsRevocationChecked    string `json:"isRevocationChecked"`
	Challenge              string `json:"challenge"`
	GistRoot               string `json:"gistRoot"`
	// MTP specific
	IssuerClaimIdenState string `json:"issuerClaimIdenState"`
}

type TestData struct {
	Desc string  `json:"desc"`
	In   Inputs  `json:"inputs"`
	Out  Outputs `json:"expOut"`
}

func Test_UserID_Subject(t *testing.T) {

	desc := "UserID = Subject. UserID out. User nonce = 0, Subject nonce = 0 claim issued on userID (Merklized claim)"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateJSONLDTestData(t, isUserIDProfile, isSubjectIDProfile, desc, "userID_subject")
}

func Test_IssueClaimToProfile(t *testing.T) {

	desc := "UserID != Subject. UserID out. User nonce = 0. Claim issued on Profile (subject nonce = 999) (Merklized claim)"
	isUserIDProfile := false
	isSubjectIDProfile := true

	generateJSONLDTestData(t, isUserIDProfile, isSubjectIDProfile, desc, "profileID_subject")
}

func Test_IssueClaimToProfile_2(t *testing.T) {

	desc := "UserID != Subject. UserProfile out. User nonce = 10. Claim issued on Profile (subject nonce = 0) (Merklized claim)"
	isUserIDProfile := true
	isSubjectIDProfile := false

	generateJSONLDTestData(t, isUserIDProfile, isSubjectIDProfile, desc, "profileID_subject_userid")
}

func Test_IssueClaimToProfile_3(t *testing.T) {

	desc := "UserID == Subject. UserProfile out. User nonce = 10. Claim issued on Profile (subject nonce = 999) (Merklized claim)"
	isUserIDProfile := true
	isSubjectIDProfile := true

	generateJSONLDTestData(t, isUserIDProfile, isSubjectIDProfile, desc, "profileID_subject_profileID2")
}

func Test_RegularClaim(t *testing.T) {

	desc := "UserID == Subject. UserID out. User nonce = 0, Subject nonce = 0 claim issued on userID (Claim)"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateTestData(t, isUserIDProfile, isSubjectIDProfile, desc, "regular_claim")
}

func Test_RevokedClaimWithoutRevocationCheck(t *testing.T) {
	desc := "ON Chain: User's claim revoked and the circuit not checking for revocation status"
	fileName := "revoked_claim_without_revocation_check"
	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)
	nonceSubject := big.NewInt(0)

	claim := utils.DefaultUserClaim(t, user.ID)
	claimSig := issuer.SignClaim(t, claim)

	revNonce := claim.GetRevocationNonce()
	revNonceBigInt := new(big.Int).SetUint64(revNonce)
	issuer.Ret.Add(context.Background(), revNonceBigInt, big.NewInt(0))
	emptyPathMtp := utils.PrepareSiblingsStr([]*merkletree.Hash{&merkletree.HashZero}, 32)

	issuerClaimNonRevState := issuer.State(t)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)
	issuerAuthClaimMtp, issuerAuthClaimNodeAux := issuer.ClaimRevMTP(t, issuer.AuthClaim)

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
		RequestID:                       requestID.String(),
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
		UserAuthClaim:                   user.AuthClaim,
		UserAuthClaimMtp:                authMTProof,
		UserAuthClaimNonRevMtp:          authNonRevMTProof,
		UserAuthClaimNonRevMtpAuxHi:     nodeAuxNonRev.Key,
		UserAuthClaimNonRevMtpAuxHv:     nodeAuxNonRev.Value,
		UserAuthClaimNonRevMtpNoAux:     nodeAuxNonRev.NoAux,
		Challenge:                       challenge.String(),
		ChallengeSignatureR8X:           sig.R8.X.String(),
		ChallengeSignatureR8Y:           sig.R8.Y.String(),
		ChallengeSignatureS:             sig.S.String(),
		UserClaimsTreeRoot:              user.Clt.Root().BigInt().String(),
		UserRevTreeRoot:                 user.Ret.Root().BigInt().String(),
		UserRootsTreeRoot:               user.Rot.Root().BigInt().String(),
		UserState:                       user.State(t).String(),
		GistRoot:                        gistRoot.BigInt().String(),
		GistMtp:                         gistProof,
		GistMtpAuxHi:                    gistNodAux.Key,
		GistMtpAuxHv:                    gistNodAux.Value,
		GistMtpNoAux:                    gistNodAux.NoAux,
		ClaimSubjectProfileNonce:        nonceSubject.String(),
		IssuerID:                        issuer.ID.BigInt().String(),
		IssuerClaim:                     claim,
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:          issuerClaimNonRevState.String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:         claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:         claimSig.R8.Y.String(),
		IssuerClaimSignatureS:           claimSig.S.String(),
		IssuerAuthClaim:                 issuer.AuthClaim,
		IssuerAuthClaimMtp:              issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:        issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi:   issuerAuthClaimNodeAux.Key,
		IssuerAuthClaimNonRevMtpAuxHv:   issuerAuthClaimNodeAux.Value,
		IssuerAuthClaimNonRevMtpNoAux:   issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsTreeRoot:        issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevTreeRoot:           issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsTreeRoot:         issuer.Rot.Root().BigInt().String(),
		ClaimSchema:                     "180410020913331409885634153623124536270",
		ClaimPathNotExists:              "0", // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:                    emptyPathMtp,
		ClaimPathMtpNoAux:               "0", // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
		ClaimPathMtpAuxHi:               "0", // 0 for inclusion proof
		ClaimPathMtpAuxHv:               "0", // 0 for inclusion proof
		ClaimPathKey:                    "0", // hash of path in merklized json-ld document
		ClaimPathValue:                  "0", // value in this path in merklized json-ld document
		// value in this path in merklized json-ld document

		Operator:            utils.EQ,
		SlotIndex:           2,
		Timestamp:           timestamp,
		IsRevocationChecked: 0,
		Value: []string{"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},

		// additional mtp inputs
		IssuerClaimIdenState:      "0",
		IssuerClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerClaimClaimsTreeRoot: "0",
		IssuerClaimRevTreeRoot:    "0",
		IssuerClaimRootsTreeRoot:  "0",

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

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
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		Timestamp:              timestamp,
		Merklized:              "0",
		СircuitQueryHash:       circuitQueryHash.String(),

		Challenge:            challenge.String(),
		GistRoot:             gistRoot.BigInt().String(),
		IsRevocationChecked:  "0",
		ProofType:            "0",
		IssuerClaimIdenState: "0",
	}

	json, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func Test_RevokedClaimWithRevocationCheck(t *testing.T) {
	desc := "User's claim revoked and the circuit checking for revocation status (expected to fail)"
	fileName := "revoked_claim_with_revocation_check"
	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)
	nonceSubject := big.NewInt(0)

	claim := utils.DefaultUserClaim(t, user.ID)
	claimSig := issuer.SignClaim(t, claim)

	revNonce := claim.GetRevocationNonce()
	revNonceBigInt := new(big.Int).SetUint64(revNonce)
	issuer.Ret.Add(context.Background(), revNonceBigInt, big.NewInt(0))
	emptyPathMtp := utils.PrepareSiblingsStr([]*merkletree.Hash{&merkletree.HashZero}, 32)

	issuerClaimNonRevState := issuer.State(t)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)
	issuerAuthClaimMtp, issuerAuthClaimNodeAux := issuer.ClaimRevMTP(t, issuer.AuthClaim)

	challenge := big.NewInt(12345)
	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 64)
	require.Nil(t, err)
	err = gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
	require.NoError(t, err)
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
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:          issuerClaimNonRevState.String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:         claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:         claimSig.R8.Y.String(),
		IssuerClaimSignatureS:           claimSig.S.String(),
		IssuerAuthClaim:                 issuer.AuthClaim,
		IssuerAuthClaimMtp:              issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:        issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi:   issuerAuthClaimNodeAux.Key,
		IssuerAuthClaimNonRevMtpAuxHv:   issuerAuthClaimNodeAux.Value,
		IssuerAuthClaimNonRevMtpNoAux:   issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsTreeRoot:        issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevTreeRoot:           issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsTreeRoot:         issuer.Rot.Root().BigInt().String(),
		ClaimSchema:                     "180410020913331409885634153623124536270",

		ClaimPathNotExists: "0", // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:       emptyPathMtp,
		ClaimPathMtpNoAux:  "0", // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
		ClaimPathMtpAuxHi:  "0", // 0 for inclusion proof
		ClaimPathMtpAuxHv:  "0", // 0 for inclusion proof
		ClaimPathKey:       "0", // hash of path in merklized json-ld document
		ClaimPathValue:     "0", // value in this path in merklized json-ld document
		// value in this path in merklized json-ld document

		Operator:            utils.EQ,
		SlotIndex:           2,
		Timestamp:           timestamp,
		IsRevocationChecked: 1,
		Value: []string{"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},

		// additional mtp inputs
		IssuerClaimIdenState:      "0",
		IssuerClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerClaimClaimsTreeRoot: "0",
		IssuerClaimRevTreeRoot:    "0",
		IssuerClaimRootsTreeRoot:  "0",

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

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
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		Timestamp:              timestamp,
		Merklized:              "0",
		СircuitQueryHash:       circuitQueryHash.String(),

		Challenge:           challenge.String(),
		GistRoot:            gistRoot.BigInt().String(),
		IsRevocationChecked: "1",

		IssuerClaimIdenState: "0",
	}

	json, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func Test_JSON_LD_Proof_non_inclusion(t *testing.T) {

	desc := "JSON-LD proof non inclusion. UserID = Subject. UserID out. User nonce = 0, " +
		"Subject nonce = 0 claim issued on userID (" +
		"Merklized claim)"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateJSONLD_NON_INCLUSIO_TestData(t, isUserIDProfile, isSubjectIDProfile, desc, "jsonld_non_inclusion")
}

func generateJSONLDTestData(t *testing.T, isUserIDProfile, isSubjectIDProfile bool, desc, fileName string) {
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

	// Sig claim
	claimSig := issuer.SignClaim(t, claim)

	issuerClaimNonRevState := issuer.State(t)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux := issuer.ClaimRevMTP(t, issuer.AuthClaim)

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
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:          issuerClaimNonRevState.String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:         claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:         claimSig.R8.Y.String(),
		IssuerClaimSignatureS:           claimSig.S.String(),
		IssuerAuthClaim:                 issuer.AuthClaim,
		IssuerAuthClaimMtp:              issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:        issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi:   issuerAuthClaimNodeAux.Key,
		IssuerAuthClaimNonRevMtpAuxHv:   issuerAuthClaimNodeAux.Value,
		IssuerAuthClaimNonRevMtpNoAux:   issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsTreeRoot:        issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevTreeRoot:           issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsTreeRoot:         issuer.Rot.Root().BigInt().String(),
		ClaimSchema:                     "180410020913331409885634153623124536270",

		ClaimPathNotExists: "0", // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:       claimJSONLDProof,
		ClaimPathMtpNoAux:  claimJSONLDProofAux.NoAux, // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
		ClaimPathMtpAuxHi:  claimJSONLDProofAux.Key,   // 0 for inclusion proof
		ClaimPathMtpAuxHv:  claimJSONLDProofAux.Value, // 0 for inclusion proof
		ClaimPathKey:       pathKey.String(),          // hash of path in merklized json-ld document
		ClaimPathValue:     valueKey.String(),         // value in this path in merklized json-ld document
		// value in this path in merklized json-ld document

		Operator:            utils.EQ,
		SlotIndex:           2,
		Timestamp:           timestamp,
		IsRevocationChecked: 1,
		Value: []string{valueKey.String(), "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},

		// additional mtp inputs
		IssuerClaimIdenState:      "0",
		IssuerClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerClaimClaimsTreeRoot: "0",
		IssuerClaimRevTreeRoot:    "0",
		IssuerClaimRootsTreeRoot:  "0",

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

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
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		Timestamp:              timestamp,
		Merklized:              "1",
		СircuitQueryHash:       circuitQueryHash.String(),
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
		IsRevocationChecked:    "1",
		ProofType:              "0",
		IssuerClaimIdenState:   "0",
	}

	json, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func generateTestData(t *testing.T, isUserIDProfile, isSubjectIDProfile bool, desc, fileName string) {
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

	// Sig claim
	claimSig := issuer.SignClaim(t, claim)

	issuerClaimNonRevState := issuer.State(t)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux := issuer.ClaimRevMTP(t, issuer.AuthClaim)

	emptyPathMtp := utils.PrepareSiblingsStr([]*merkletree.Hash{&merkletree.HashZero}, 32)

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
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:          issuerClaimNonRevState.String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:         claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:         claimSig.R8.Y.String(),
		IssuerClaimSignatureS:           claimSig.S.String(),
		IssuerAuthClaim:                 issuer.AuthClaim,
		IssuerAuthClaimMtp:              issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:        issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi:   issuerAuthClaimNodeAux.Key,
		IssuerAuthClaimNonRevMtpAuxHv:   issuerAuthClaimNodeAux.Value,
		IssuerAuthClaimNonRevMtpNoAux:   issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsTreeRoot:        issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevTreeRoot:           issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsTreeRoot:         issuer.Rot.Root().BigInt().String(),
		ClaimSchema:                     "180410020913331409885634153623124536270",

		ClaimPathNotExists: "0", // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:       emptyPathMtp,
		ClaimPathMtpNoAux:  "0", // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
		ClaimPathMtpAuxHi:  "0", // 0 for inclusion proof
		ClaimPathMtpAuxHv:  "0", // 0 for inclusion proof
		ClaimPathKey:       "0", // hash of path in merklized json-ld document
		ClaimPathValue:     "0", // value in this path in merklized json-ld document
		// value in this path in merklized json-ld document

		Operator:            utils.EQ,
		SlotIndex:           2,
		Timestamp:           timestamp,
		IsRevocationChecked: 1,
		Value: []string{"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},

		// additional mtp inputs
		IssuerClaimIdenState:      "0",
		IssuerClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerClaimClaimsTreeRoot: "0",
		IssuerClaimRevTreeRoot:    "0",
		IssuerClaimRootsTreeRoot:  "0",

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

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
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		Timestamp:              timestamp,
		Merklized:              "0",
		СircuitQueryHash:       circuitQueryHash.String(),

		Challenge: challenge.String(),
		GistRoot:  gistRoot.BigInt().String(),

		IsRevocationChecked:  "1",
		IssuerClaimIdenState: "0",
		ProofType:            "0",
	}

	json, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func generateJSONLD_NON_INCLUSIO_TestData(t *testing.T, isUserIDProfile, isSubjectIDProfile bool, desc,
	fileName string) {

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
		"https://w3id.org/citizenship#testData")
	require.NoError(t, err)

	jsonP, _, err := mz.Proof(context.Background(), path)

	claimJSONLDProof, claimJSONLDProofAux := utils.PrepareProof(jsonP, utils.ClaimLevels)

	pathKey, err := path.MtEntry()
	require.NoError(t, err)

	// Sig claim
	claimSig := issuer.SignClaim(t, claim)

	issuerClaimNonRevState := issuer.State(t)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux := issuer.ClaimRevMTP(t, issuer.AuthClaim)

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
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:          issuerClaimNonRevState.String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:         claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:         claimSig.R8.Y.String(),
		IssuerClaimSignatureS:           claimSig.S.String(),
		IssuerAuthClaim:                 issuer.AuthClaim,
		IssuerAuthClaimMtp:              issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:        issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi:   issuerAuthClaimNodeAux.Key,
		IssuerAuthClaimNonRevMtpAuxHv:   issuerAuthClaimNodeAux.Value,
		IssuerAuthClaimNonRevMtpNoAux:   issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsTreeRoot:        issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevTreeRoot:           issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsTreeRoot:         issuer.Rot.Root().BigInt().String(),
		ClaimSchema:                     "180410020913331409885634153623124536270",

		ClaimPathNotExists: "1", // 0 for inclusion, 1 for non-inclusion
		ClaimPathMtp:       claimJSONLDProof,
		ClaimPathMtpNoAux:  claimJSONLDProofAux.NoAux, // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
		ClaimPathMtpAuxHi:  claimJSONLDProofAux.Key,   // 0 for inclusion proof
		ClaimPathMtpAuxHv:  claimJSONLDProofAux.Value, // 0 for inclusion proof
		ClaimPathKey:       pathKey.String(),          // hash of path in merklized json-ld document
		ClaimPathValue:     "0",                       // value in this path in merklized json-ld document
		// value in this path in merklized json-ld document

		Operator:            utils.NOOP,
		SlotIndex:           0,
		Timestamp:           timestamp,
		IsRevocationChecked: 1,
		Value: []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},

		// additional mtp inputs
		IssuerClaimIdenState:      "0",
		IssuerClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerClaimClaimsTreeRoot: "0",
		IssuerClaimRevTreeRoot:    "0",
		IssuerClaimRootsTreeRoot:  "0",

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

	valuesHash, err := utils.PoseidonHashValue(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)
	claimSchemaInt, ok := big.NewInt(0).SetString(inputs.ClaimSchema, 10)
	require.True(t, ok)
	circuitQueryHash, err := poseidon.Hash([]*big.Int{
		claimSchemaInt,
		big.NewInt(int64(inputs.SlotIndex)),
		big.NewInt(int64(inputs.Operator)),
		pathKey,
		big.NewInt(1),
		valuesHash,
	})
	require.NoError(t, err)

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		Timestamp:              timestamp,
		Merklized:              "1",
		СircuitQueryHash:       circuitQueryHash.String(),

		Challenge:            challenge.String(),
		GistRoot:             gistRoot.BigInt().String(),
		IsRevocationChecked:  "1",
		IssuerClaimIdenState: "0",
		ProofType:            "0",
	}

	json, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
