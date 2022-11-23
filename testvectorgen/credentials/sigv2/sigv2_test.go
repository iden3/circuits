package sigv2

import (
	"context"
	json2 "encoding/json"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/stretchr/testify/require"
	"test/utils"
)

const (
	userPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	issuerPK  = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
)

type CredentialAtomicSigOffChainV2Inputs struct {
	// user data
	UserGenesisID            string `json:"userGenesisID"`
	Nonce                    string `json:"nonce"`
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"`

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

	Operator  int      `json:"operator"`
	SlotIndex int      `json:"slotIndex"`
	Timestamp string   `json:"timestamp"`
	Value     []string `json:"value"`
}

type CredentialAtomicSigOffChainV2Outputs struct {
	UserID                 string   `json:"userID"`
	IssuerID               string   `json:"issuerID"`
	IssuerAuthState        string   `json:"issuerAuthState"`
	IssuerClaimNonRevState string   `json:"issuerClaimNonRevState"`
	ClaimSchema            string   `json:"claimSchema"`
	SlotIndex              string   `json:"slotIndex"`
	Operator               int      `json:"operator"`
	Value                  []string `json:"value"`
	Timestamp              string   `json:"timestamp"`
	Merklized              string   `json:"merklized"`
	ClaimPathNotExists     string   `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
}

type TestDataSigV2 struct {
	Desc string                               `json:"desc"`
	In   CredentialAtomicSigOffChainV2Inputs  `json:"inputs"`
	Out  CredentialAtomicSigOffChainV2Outputs `json:"expOut"`
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

	claimJSONLDProof, claimJSONLDProofAux := utils.PrepareProof(jsonP)

	pathKey, err := path.MtEntry()
	require.NoError(t, err)

	// Sig claim
	claimSig := issuer.SignClaim(t, claim)

	issuerClaimNonRevState := issuer.State(t)

	issuerClaimNonRevMtp, issuerClaimNonRevAux, err := issuer.ClaimRevMTP(claim)
	require.NoError(t, err)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux, err := issuer.ClaimRevMTP(issuer.AuthClaim)

	inputs := CredentialAtomicSigOffChainV2Inputs{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           nonce.String(),
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

		Operator:  utils.EQ,
		SlotIndex: 2,
		Timestamp: timestamp,
		Value: []string{valueKey.String(), "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
	}

	issuerAuthState := issuer.State(t)

	out := CredentialAtomicSigOffChainV2Outputs{
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		Value:                  []string{"1420070400000000000", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		Timestamp:              timestamp,
		Merklized:              "1",
		ClaimPathNotExists:     "0",
	}

	json, err := json2.Marshal(TestDataSigV2{
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
	require.NoError(t, err)

	issuer := utils.NewIdentity(t, issuerPK)
	require.NoError(t, err)

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

	issuerClaimNonRevMtp, issuerClaimNonRevAux, err := issuer.ClaimRevMTP(claim)
	require.NoError(t, err)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux, err := issuer.ClaimRevMTP(issuer.AuthClaim)

	emptyPathMtp := utils.PrepareSiblingsStr([]*merkletree.Hash{&merkletree.HashZero}, 32)

	inputs := CredentialAtomicSigOffChainV2Inputs{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           nonce.String(),
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

		Operator:  utils.EQ,
		SlotIndex: 2,
		Timestamp: timestamp,
		Value: []string{"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
	}

	issuerAuthState := issuer.State(t)

	out := CredentialAtomicSigOffChainV2Outputs{
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		Value: []string{"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		Timestamp:          timestamp,
		Merklized:          "0",
		ClaimPathNotExists: "0",
	}

	json, err := json2.Marshal(TestDataSigV2{
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

	claimJSONLDProof, claimJSONLDProofAux := utils.PrepareProof(jsonP)

	pathKey, err := path.MtEntry()
	require.NoError(t, err)

	// Sig claim
	claimSig := issuer.SignClaim(t, claim)

	issuerClaimNonRevState := issuer.State(t)

	issuerClaimNonRevMtp, issuerClaimNonRevAux, err := issuer.ClaimRevMTP(claim)
	require.NoError(t, err)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux, err := issuer.ClaimRevMTP(issuer.AuthClaim)

	inputs := CredentialAtomicSigOffChainV2Inputs{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           nonce.String(),
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

		Operator:  utils.NOOP,
		SlotIndex: 0,
		Timestamp: timestamp,
		Value: []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
	}

	issuerAuthState := issuer.State(t)

	out := CredentialAtomicSigOffChainV2Outputs{
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "0",
		Operator:               utils.NOOP,
		Value: []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		Timestamp:          timestamp,
		Merklized:          "1",
		ClaimPathNotExists: "1",
	}

	json, err := json2.Marshal(TestDataSigV2{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
