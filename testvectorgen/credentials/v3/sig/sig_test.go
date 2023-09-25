package v3

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"test/utils"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/stretchr/testify/require"
)

const (
	userPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	issuerPK  = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
)

type Inputs struct {
	RequestID string `json:"requestID"`

	// user data
	UserGenesisID            string `json:"userGenesisID"`
	ProfileNonce             string `json:"profileNonce"`
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

	// Private random nonce, used to generate LinkID
	LinkNonce string `json:"linkNonce"`

	ProofType string `json:"proofType"`
}

type Outputs struct {
	RequestID              string   `json:"requestID"`
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
	ProofType              string   `json:"proofType"`
	ClaimPathKey           string   `json:"claimPathKey"`
	IssuerClaimIdenState   string   `json:"issuerClaimIdenState"`
	LinkID                 string   `json:"linkID"`
	OperatorOutput         string   `json:"operatorOutput"`
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

	generateTestData(t, isUserIDProfile, isSubjectIDProfile, desc, "0", "regular_claim")
}

func Test_RevokedClaimWithoutRevocationCheck(t *testing.T) {
	desc := "User's claim revoked and the circuit not checking for revocation status"
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

	requestID := big.NewInt(23)

	inputs := Inputs{
		RequestID:                       requestID.String(),
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
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

		LinkNonce: "0",

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 user.ID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		Value: []string{"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		Timestamp:            timestamp,
		Merklized:            "0",
		ClaimPathNotExists:   "0",
		ProofType:            "0",
		ClaimPathKey:         "0",
		IssuerClaimIdenState: "0",
		LinkID:               "0",
		OperatorOutput:       "0",
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

	requestID := big.NewInt(23)

	inputs := Inputs{
		RequestID:                       requestID.String(),
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
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

		LinkNonce: "0",

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 user.ID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		Value: []string{"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		Timestamp:            timestamp,
		Merklized:            "0",
		ClaimPathNotExists:   "0",
		ProofType:            "0",
		ClaimPathKey:         "0",
		IssuerClaimIdenState: "0",
		LinkID:               "0",
		OperatorOutput:       "0",
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

func Test_LinkID(t *testing.T) {
	desc := "LinkId not 0"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateTestData(t, isUserIDProfile, isSubjectIDProfile, desc, "94324", "claimWithLinkNonce")
}

func Test_Nullify(t *testing.T) {
	desc := "Nullify modifier"
	isUserIDProfile := true
	isSubjectIDProfile := true
	operator := int(utils.NULLIFY)
	value := utils.PrepareStrArray([]string{"94313"}, 64)
	generateTestDataWithOperaor(t, isUserIDProfile, isSubjectIDProfile, desc, "0", "nullify_modifier", &operator, &value)
}

func Test_Selective_Disclosure(t *testing.T) {
	desc := "Selective Disclosure modifier"
	isUserIDProfile := true
	isSubjectIDProfile := true
	operator := int(utils.SD)
	value := utils.PrepareStrArray([]string{}, 64)
	generateTestDataWithOperaor(t, isUserIDProfile, isSubjectIDProfile, desc, "0", "selective_disclosure", &operator, &value)
}

func Test_Between(t *testing.T) {
	desc := "Between operator"
	isUserIDProfile := false
	isSubjectIDProfile := false
	operator := int(utils.BETWEEN)
	value := utils.PrepareStrArray([]string{"8", "10"}, 64)
	generateTestDataWithOperaor(t, isUserIDProfile, isSubjectIDProfile, desc, "0", "between_operator", &operator, &value)
}

func Test_Less_Than_Eq(t *testing.T) {
	desc := "LTE operator"
	isUserIDProfile := false
	isSubjectIDProfile := false
	operator := int(utils.LTE)
	value := utils.PrepareStrArray([]string{"10"}, 64)
	generateTestDataWithOperaor(t, isUserIDProfile, isSubjectIDProfile, desc, "0", "less_than_eq_operator", &operator, &value)
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

	requestID := big.NewInt(23)

	inputs := Inputs{
		RequestID:                       requestID.String(),
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
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

		LinkNonce: "0",

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

	out := Outputs{
		RequestID:              requestID.String(),
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
		ProofType:              "0",
		ClaimPathKey:           pathKey.String(),
		IssuerClaimIdenState:   "0",
		LinkID:                 "0",
		OperatorOutput:         "0",
	}

	json, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func generateTestData(t *testing.T, isUserIDProfile, isSubjectIDProfile bool, desc,
	linkNonce string, fileName string) {
	generateTestDataWithOperaor(t, isUserIDProfile, isSubjectIDProfile, desc, linkNonce, fileName, nil, nil)
}

func generateTestDataWithOperaor(t *testing.T, isUserIDProfile, isSubjectIDProfile bool, desc,
	linkNonce string, fileName string, operator *int, value *[]string) {
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

	requestID := big.NewInt(23)

	linkID, err := utils.CalculateLinkID(linkNonce, claim)
	require.NoError(t, err)

	operatorInput := utils.EQ
	if operator != nil {
		operatorInput = *operator
	}
	valueInput := utils.PrepareStrArray([]string{"10"}, 64)
	if value != nil {
		valueInput = *value
	}

	inputs := Inputs{
		RequestID:                       requestID.String(),
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
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

		Operator:            operatorInput,
		SlotIndex:           2,
		Timestamp:           timestamp,
		IsRevocationChecked: 1,
		Value:               valueInput,

		// additional mtp inputs
		IssuerClaimIdenState:      "0",
		IssuerClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerClaimClaimsTreeRoot: "0",
		IssuerClaimRevTreeRoot:    "0",
		IssuerClaimRootsTreeRoot:  "0",

		LinkNonce: linkNonce,

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

	operatorOutput := "0"
	if operatorInput == utils.NULLIFY {
		crs, ok := big.NewInt(0).SetString(valueInput[0], 10)
		require.True(t, ok)

		operatorOutput, err = utils.CalculateNullify(user.ID.BigInt(), nonceSubject, big.NewInt(10), crs)
		require.NoError(t, err)
	} else if operatorInput == utils.SD {
		operatorOutput = big.NewInt(10).String()
	}

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               operatorInput,
		Value:                  valueInput,
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathNotExists:     "0",
		ProofType:              "0",
		ClaimPathKey:           "0",
		IssuerClaimIdenState:   "0",
		LinkID:                 linkID,
		OperatorOutput:         operatorOutput,
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

	requestID := big.NewInt(23)

	inputs := Inputs{
		RequestID:                       requestID.String(),
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
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

		LinkNonce: "0",

		ProofType: "0",
	}

	issuerAuthState := issuer.State(t)

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "0",
		Operator:               utils.NOOP,
		Value: []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		Timestamp:            timestamp,
		Merklized:            "1",
		ClaimPathNotExists:   "1",
		ProofType:            "0",
		ClaimPathKey:         pathKey.String(),
		IssuerClaimIdenState: "0",
		LinkID:               "0",
		OperatorOutput:       "0",
	}

	json, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
