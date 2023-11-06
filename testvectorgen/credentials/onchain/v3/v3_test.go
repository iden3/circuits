package v3

import (
	"context"
	"encoding/json"
	"math/big"
	"strconv"
	"testing"

	"test/utils"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/stretchr/testify/require"
)

const (
	userPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	issuerPK  = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
)

var requestID = big.NewInt(41)

type ProofType string

const (
	Sig ProofType = "sig"
	Mtp ProofType = "mtp"
)

type Inputs struct {
	RequestID string `json:"requestID"`

	// user data
	UserGenesisID            string `json:"userGenesisID"`            //
	ProfileNonce             string `json:"profileNonce"`             //
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"` //

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
	IssuerAuthState               string      `json:"issuerAuthState"`

	ProofType string `json:"proofType"` // 1 for sig, 2 for mtp

	// Private random nonce, used to generate LinkID
	LinkNonce string `json:"linkNonce"`

	VerifierID        string `json:"verifierID"`
	VerifierSessionID string `json:"verifierSessionID"`
}

type Outputs struct {
	RequestID              string `json:"requestID"`
	UserID                 string `json:"userID"`
	IssuerID               string `json:"issuerID"`
	IssuerClaimNonRevState string `json:"issuerClaimNonRevState"`
	CircuitQueryHash       string `json:"circuitQueryHash"`
	GistRoot               string `json:"gistRoot"`
	Timestamp              string `json:"timestamp"`
	Merklized              string `json:"merklized"`
	ProofType              string `json:"proofType"` // 1 for sig, 2 for mtp
	IsRevocationChecked    string `json:"isRevocationChecked"`
	Challenge              string `json:"challenge"`
	IssuerState            string `json:"issuerState"`
	LinkID                 string `json:"linkID"`
	VerifierID             string `json:"verifierID"`
	VerifierSessionID      string `json:"verifierSessionID"`
	OperatorOutput         string `json:"operatorOutput"`
	Nullifier              string `json:"nullifier"`
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

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "mtp/claimIssuedOnUserID", Mtp)
	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "sig/claimIssuedOnUserID", Sig)
}

func Test_ClaimIssuedOnUserProfileID(t *testing.T) {
	desc := "User != Subject. Claim issued on ProfileID"
	isUserIDProfile := false
	isSubjectIDProfile := true

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "mtp/claimIssuedOnProfileID", Mtp)
	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "sig/claimIssuedOnProfileID", Sig)
}

func Test_IssueClaimToProfile(t *testing.T) {

	desc := "UserID != Subject. UserProfile out. User nonce = 10. Claim issued on Profile (subject nonce = 0) (Merklized claim)"
	isUserIDProfile := true
	isSubjectIDProfile := false

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "mtp/profileID_subject_userid", Mtp)
	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "sig/profileID_subject_userid", Sig)
}

func Test_ClaimIssuedOnUserProfileID2(t *testing.T) {
	desc := "User == Subject. Claim issued on ProfileID"
	isUserIDProfile := true
	isSubjectIDProfile := true

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "mtp/claimIssuedOnProfileID2", Mtp)
	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "sig/claimIssuedOnProfileID2", Sig)
}

func Test_ClaimNonMerklized(t *testing.T) {
	desc := "User == Subject. Claim non merklized claim"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/claimNonMerklized", Mtp)
	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/claimNonMerklized", Sig)
}

func Test_RevokedClaimWithRevocationCheck(t *testing.T) {
	desc := "User's claim revoked and the circuit checking for revocation status (expected to fail)"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateRevokedTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/revoked_claim_with_revocation_check", 1, Sig)
	generateRevokedTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/revoked_claim_with_revocation_check", 1, Mtp)
}

func Test_RevokedClaimWithoutRevocationCheck(t *testing.T) {
	desc := "User's claim revoked and the circuit not checking for revocation status"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateRevokedTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/revoked_claim_without_revocation_check", 0, Sig)
	generateRevokedTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/revoked_claim_without_revocation_check", 0, Mtp)
}

func Test_JSON_LD_Proof_non_inclusion(t *testing.T) {

	desc := "JSON-LD proof non inclusion. UserID = Subject. UserID out. User nonce = 0, " +
		"Subject nonce = 0 claim issued on userID (" +
		"Merklized claim)"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateJSONLD_NON_INCLUSION_TestData(t, isUserIDProfile, isSubjectIDProfile, desc, "sig/jsonld_non_inclusion")
}

func Test_LinkID(t *testing.T) {
	desc := "LinkId not 0"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "6321", "mtp/claimWithLinkNonce", Mtp)
	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "6321", "sig/claimWithLinkNonce", Sig)
}

func Test_Nullify(t *testing.T) {
	desc := "Nullify"
	isUserIDProfile := true
	isSubjectIDProfile := true
	value := utils.PrepareStrArray([]string{"94313"}, 64)
	// FIXME: pass verifier session id
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/nullify", utils.NOOP, &value, Mtp)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/nullify", utils.NOOP, &value, Sig)
}

func Test_Selective_Disclosure(t *testing.T) {
	desc := "Selective Disclosure modifier"
	isUserIDProfile := true
	isSubjectIDProfile := true
	value := utils.PrepareStrArray([]string{}, 64)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/selective_disclosure", utils.SD, &value, Mtp)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/selective_disclosure", utils.SD, &value, Sig)
}

func Test_Between(t *testing.T) {
	desc := "Between operator"
	isUserIDProfile := false
	isSubjectIDProfile := false
	value := utils.PrepareStrArray([]string{"8", "10"}, 64)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/between_operator", utils.BETWEEN, &value, Mtp)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/between_operator", utils.BETWEEN, &value, Sig)
}

func Test_Less_Than_Eq(t *testing.T) {
	desc := "LTE operator"
	isUserIDProfile := false
	isSubjectIDProfile := false
	value := utils.PrepareStrArray([]string{"10"}, 64)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/less_than_eq_operator", utils.LTE, &value, Mtp)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/less_than_eq_operator", utils.LTE, &value, Sig)
}

func generateTestData(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool,
	linkNonce string, fileName string, proofType ProofType) {
	generateTestDataWithOperatorAndRevCheck(t, desc, isUserIDProfile, isSubjectIDProfile, linkNonce, "0", fileName, utils.EQ, nil, false, 1, false, proofType)
}

func generateRevokedTestData(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool,
	linkNonce string, fileName string, isRevocationChecked int, proofType ProofType) {
	generateTestDataWithOperatorAndRevCheck(t, desc, isUserIDProfile, isSubjectIDProfile, linkNonce, "0", fileName, utils.EQ, nil, true, isRevocationChecked, false, proofType)
}

func generateTestDataWithOperator(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool,
	linkNonce string, fileName string, operator int, value *[]string, proofType ProofType) {
	generateTestDataWithOperatorAndRevCheck(t, desc, isUserIDProfile, isSubjectIDProfile, linkNonce, "0", fileName, operator, value, false, 1, false, proofType)
}

func generateJSONLDTestData(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool, fileName string, proofType ProofType) {
	generateTestDataWithOperatorAndRevCheck(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "0", fileName, utils.EQ, nil, false, 1, true, proofType)
}

func generateTestDataWithOperatorAndRevCheck(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool,
	linkNonce, verifierSessionID, fileName string, operator int, value *[]string, isRevoked bool, isRevocationChecked int, isJSONLD bool, testProofType ProofType) {
	var err error

	valueInput := utils.PrepareStrArray([]string{"10"}, 64)
	if value != nil {
		valueInput = *value
	}

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

	var claim *core.Claim
	var mz *merklize.Merklizer
	var claimPathMtp []string
	var claimPathMtpNoAux, claimPathMtpAuxHi, claimPathMtpAuxHv, claimPathKey, claimPathValue, merklized string
	var pathKey *big.Int

	if isJSONLD {
		mz, claim = utils.DefaultJSONUserClaim(t, subjectID)
		path, err := merklize.NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject",
			"https://w3id.org/citizenship#residentSince")
		require.NoError(t, err)
		jsonP, value, err := mz.Proof(context.Background(), path)
		require.NoError(t, err)
		valueKey, err := value.MtEntry()
		require.NoError(t, err)
		claimPathValue = valueKey.String()

		var claimJSONLDProofAux utils.NodeAuxValue
		claimPathMtp, claimJSONLDProofAux = utils.PrepareProof(jsonP, utils.ClaimLevels)
		claimPathMtpNoAux = claimJSONLDProofAux.NoAux
		claimPathMtpAuxHi = claimJSONLDProofAux.Key
		claimPathMtpAuxHv = claimJSONLDProofAux.Value
		pathKey, err = path.MtEntry()
		require.NoError(t, err)
		claimPathKey = pathKey.String()

		valueInput = utils.PrepareStrArray([]string{claimPathValue}, 64)
		merklized = "1"

	} else {
		claim = utils.DefaultUserClaim(t, subjectID)
		claimPathMtp = utils.PrepareStrArray([]string{}, 32)
		claimPathMtpNoAux = "0"
		claimPathMtpAuxHi = "0"
		claimPathMtpAuxHv = "0"
		claimPathKey = "0"
		claimPathValue = "0"
		merklized = "0"
		pathKey = big.NewInt(0)
	}

	if isRevoked {
		revNonce := claim.GetRevocationNonce()
		revNonceBigInt := new(big.Int).SetUint64(revNonce)
		issuer.Ret.Add(context.Background(), revNonceBigInt, big.NewInt(0))
	}

	var issuerClaimMtp, issuerAuthClaimMtp []string
	var issuerClaimClaimsTreeRoot, issuerClaimRevTreeRoot, issuerClaimRootsTreeRoot *merkletree.Hash
	var issuerClaimSignatureR8X, issuerClaimSignatureR8Y, issuerClaimSignatureS,
		issuerAuthClaimNonRevMtpAuxHi, issuerAuthClaimNonRevMtpAuxHv, issuerAuthClaimNonRevMtpNoAux,
		issuerClaimIdenState, proofType, issuerAuthClaimsTreeRoot,
		issuerAuthRevTreeRoot, issuerAuthRootsTreeRoot, issuerAuthState string
	var issuerAuthClaim *core.Claim
	var slotIndex int
	if testProofType == Sig {
		// Sig claim
		claimSig := issuer.SignClaim(t, claim)
		var issuerAuthClaimNodeAux utils.NodeAuxValue
		issuerAuthClaimMtp, issuerAuthClaimNodeAux = issuer.ClaimRevMTP(t, issuer.AuthClaim)

		issuerClaimMtp = utils.PrepareStrArray([]string{}, 40)
		issuerClaimClaimsTreeRoot = &merkletree.HashZero
		issuerClaimRevTreeRoot = &merkletree.HashZero
		issuerClaimRootsTreeRoot = &merkletree.HashZero

		issuerAuthClaimNonRevMtpAuxHi = issuerAuthClaimNodeAux.Key
		issuerAuthClaimNonRevMtpAuxHv = issuerAuthClaimNodeAux.Value
		issuerAuthClaimNonRevMtpNoAux = issuerAuthClaimNodeAux.NoAux

		issuerClaimSignatureR8X = claimSig.R8.X.String()
		issuerClaimSignatureR8Y = claimSig.R8.Y.String()
		issuerClaimSignatureS = claimSig.S.String()

		issuerAuthClaim = issuer.AuthClaim

		issuerClaimIdenState = "0"

		issuerAuthClaimsTreeRoot = issuer.Clt.Root().BigInt().String()
		issuerAuthRevTreeRoot = issuer.Ret.Root().BigInt().String()
		issuerAuthRootsTreeRoot = issuer.Rot.Root().BigInt().String()

		issuerAuthState = issuer.State(t).String()

		slotIndex = 2

		proofType = "1"
	} else {
		issuer.AddClaim(t, claim)
		issuerClaimMtp, _ = issuer.ClaimMTP(t, claim)
		issuerClaimIdenState = issuer.State(t).String()

		issuerClaimClaimsTreeRoot = issuer.Clt.Root()
		issuerClaimRevTreeRoot = issuer.Ret.Root()
		issuerClaimRootsTreeRoot = issuer.Rot.Root()

		issuerClaimSignatureR8X = "0"
		issuerClaimSignatureR8Y = "0"
		issuerClaimSignatureS = "0"

		issuerAuthClaimNonRevMtpAuxHi = "0"
		issuerAuthClaimNonRevMtpAuxHv = "0"
		issuerAuthClaimNonRevMtpNoAux = "0"

		issuerAuthClaimMtp = utils.PrepareStrArray([]string{}, 40)

		issuerAuthClaim = &core.Claim{}

		issuerAuthClaimsTreeRoot = "0"
		issuerAuthRevTreeRoot = "0"
		issuerAuthRootsTreeRoot = "0"

		issuerAuthState = "0"

		slotIndex = 2
		proofType = "2"
	}

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
		IssuerClaimMtp:                  issuerClaimMtp,
		IssuerClaimClaimsTreeRoot:       issuerClaimClaimsTreeRoot,
		IssuerClaimRevTreeRoot:          issuerClaimRevTreeRoot,
		IssuerClaimRootsTreeRoot:        issuerClaimRootsTreeRoot,
		IssuerClaimIdenState:            issuerClaimIdenState,
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
		ClaimPathMtp:                    claimPathMtp,
		ClaimPathMtpNoAux:               claimPathMtpNoAux,
		ClaimPathMtpAuxHi:               claimPathMtpAuxHi,
		ClaimPathMtpAuxHv:               claimPathMtpAuxHv,
		ClaimPathKey:                    claimPathKey,
		ClaimPathValue:                  claimPathValue,
		IsRevocationChecked:             isRevocationChecked,
		Operator:                        operator,
		SlotIndex:                       slotIndex,
		Timestamp:                       timestamp,
		Value:                           valueInput,

		IssuerClaimSignatureR8X:       issuerClaimSignatureR8X,
		IssuerClaimSignatureR8Y:       issuerClaimSignatureR8Y,
		IssuerClaimSignatureS:         issuerClaimSignatureS,
		IssuerAuthClaim:               issuerAuthClaim,
		IssuerAuthClaimMtp:            issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:      issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi: issuerAuthClaimNonRevMtpAuxHi,
		IssuerAuthClaimNonRevMtpAuxHv: issuerAuthClaimNonRevMtpAuxHv,
		IssuerAuthClaimNonRevMtpNoAux: issuerAuthClaimNonRevMtpNoAux,
		IssuerAuthClaimsTreeRoot:      issuerAuthClaimsTreeRoot,
		IssuerAuthRevTreeRoot:         issuerAuthRevTreeRoot,
		IssuerAuthRootsTreeRoot:       issuerAuthRootsTreeRoot,
		IssuerAuthState:               issuerAuthState,

		LinkNonce: linkNonce,

		ProofType: proofType,

		VerifierID:        "21929109382993718606847853573861987353620810345503358891473103689157378049",
		VerifierSessionID: verifierSessionID,
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

	linkID, err := utils.CalculateLinkID(linkNonce, claim)
	require.NoError(t, err)

	operatorOutput := "0"
	nullifier := "0"
	if inputs.VerifierSessionID != "0" {
		claimSchema, ok := big.NewInt(0).SetString(inputs.ClaimSchema, 10)
		require.True(t, ok)

		verifierID, ok := big.NewInt(0).SetString(inputs.VerifierID, 10)
		require.True(t, ok)

		verifierSessionID_, ok := big.NewInt(0).SetString(inputs.VerifierSessionID, 10)
		require.True(t, ok)

		nullifier, err = utils.CalculateNullify(
			user.ID.BigInt(),
			nonceSubject,
			claimSchema,
			verifierID,
			verifierSessionID_,
		)
		require.NoError(t, err)
	}

	if operator == utils.SD {
		operatorOutput = big.NewInt(10).String()
	}

	var issuerState string
	if proofType == "1" {
		// sig
		issuerState = issuerAuthState
	} else {
		// mtp
		issuerState = issuerClaimIdenState
	}

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		CircuitQueryHash:       circuitQueryHash.String(),
		Timestamp:              timestamp,
		Merklized:              merklized,
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
		IsRevocationChecked:    strconv.Itoa(isRevocationChecked),
		ProofType:              proofType,
		IssuerState:            issuerState,
		LinkID:                 linkID,
		OperatorOutput:         operatorOutput,
		VerifierID:             inputs.VerifierID,
		VerifierSessionID:      inputs.VerifierSessionID,
		Nullifier:              nullifier,
	}

	jsonData, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonData))
}

func generateJSONLD_NON_INCLUSION_TestData(t *testing.T, isUserIDProfile, isSubjectIDProfile bool, desc,
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
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root(),
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
		IssuerAuthState:                 issuer.State(t).String(),
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
		Value:               utils.PrepareStrArray([]string{}, 64),

		// additional mtp inputs
		IssuerClaimIdenState:      "0",
		IssuerClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerClaimClaimsTreeRoot: &merkletree.HashZero,
		IssuerClaimRevTreeRoot:    &merkletree.HashZero,
		IssuerClaimRootsTreeRoot:  &merkletree.HashZero,

		LinkNonce: "0",

		ProofType: "1",

		VerifierID:        "21929109382993718606847853573861987353620810345503358891473103689157378049",
		VerifierSessionID: "0",
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
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		Timestamp:              timestamp,
		Merklized:              "1",
		CircuitQueryHash:       circuitQueryHash.String(),
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
		IssuerState:            issuerAuthState.String(),
		IsRevocationChecked:    "1",
		ProofType:              "1",
		LinkID:                 "0",
		VerifierID:             inputs.VerifierID,
		VerifierSessionID:      inputs.VerifierSessionID,
		OperatorOutput:         "0",
		Nullifier:              "0",
	}

	jsonData, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonData))
}
