package v3

import (
	"context"
	"encoding/json"
	"math/big"
	"strconv"
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
	UserGenesisID            string `json:"userGenesisID"`            //
	ProfileNonce             string `json:"profileNonce"`             //
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"` //

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

	// Private random nonce, used to generate LinkID
	LinkNonce string `json:"linkNonce"`

	ProofType string `json:"proofType"` // 0 for sig, 1 for mtp
}

type Outputs struct {
	RequestID              string   `json:"requestID"`
	UserID                 string   `json:"userID"`
	IssuerID               string   `json:"issuerID"`
	IssuerClaimIdenState   string   `json:"issuerClaimIdenState"`
	IssuerClaimNonRevState string   `json:"issuerClaimNonRevState"`
	ClaimSchema            string   `json:"claimSchema"`
	SlotIndex              string   `json:"slotIndex"`
	Operator               int      `json:"operator"`
	Value                  []string `json:"value"`
	Timestamp              string   `json:"timestamp"`
	Merklized              string   `json:"merklized"`
	ClaimPathKey           string   `json:"claimPathKey"`
	ClaimPathNotExists     string   `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	ProofType              string   `json:"proofType"`          // 0 for sig, 1 for mtp
	IssuerAuthState        string   `json:"issuerAuthState"`
	LinkID                 string   `json:"linkID"`
	OperatorOutput         string   `json:"operatorOutput"`
}

type TestData struct {
	Desc string  `json:"desc"`
	In   Inputs  `json:"inputs"`
	Out  Outputs `json:"expOut"`
}

type TestType string

const (
	Sig TestType = "sig"
	Mtp TestType = "mtp"
)

func Test_ClaimIssuedOnUserID(t *testing.T) {
	desc := "User == Subject. Claim issued on UserID"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "sig/claimIssuedOnUserID", Sig)
	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "mtp/claimIssuedOnUserID", Mtp)
}

func Test_ClaimIssuedOnUserProfileID(t *testing.T) {
	desc := "User != Subject. Claim issued on ProfileID"
	isUserIDProfile := false
	isSubjectIDProfile := true

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "sig/profileID_subject", Sig)
	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "mtp/profileID_subject", Mtp)
}

func Test_IssueClaimToProfile(t *testing.T) {

	desc := "UserID != Subject. UserProfile out. Claim issued on Profile (subject nonce = 0)"
	isUserIDProfile := true
	isSubjectIDProfile := false

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "sig/claimIssuedOnProfileID", Sig)
	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "mtp/claimIssuedOnProfileID", Mtp)
}

func Test_ClaimIssuedOnUserProfileID2(t *testing.T) {
	desc := "User == Subject. Claim issued on ProfileID"
	isUserIDProfile := true
	isSubjectIDProfile := true

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "sig/claimIssuedOnProfileID2", Sig)
	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "mtp/claimIssuedOnProfileID2", Mtp)
}

func Test_ClaimNonMerklized(t *testing.T) {
	desc := "User == Subject. Claim non merklized claim"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/claimNonMerklized", Sig)
	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/claimNonMerklized", Mtp)
}

func Test_RevokedClaimWithRevocationCheckMtp(t *testing.T) {
	desc := "User's claim revoked and the circuit checking for revocation status (expected to fail)"
	fileName := "mtp/revoked_claim_with_revocation_check"

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

	requestID := big.NewInt(23)

	inputs := Inputs{
		RequestID:                       requestID.String(),
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
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

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 user.ID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		Value:                  utils.PrepareStrArray([]string{"10"}, 64),
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathKey:           "0",
		ClaimPathNotExists:     "0", // 0 for inclusion, 1 for non-inclusion
		ProofType:              "1",
		IssuerAuthState:        "0",
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

func Test_RevokedClaimWithRevocationCheckSig(t *testing.T) {
	desc := "User's claim revoked and the circuit checking for revocation status (expected to fail)"
	fileName := "sig/revoked_claim_with_revocation_check"
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
		Value:               utils.PrepareStrArray([]string{"10"}, 64),

		// additional mtp inputs
		IssuerClaimIdenState:      "0",
		IssuerClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerClaimClaimsTreeRoot: &merkletree.HashZero,
		IssuerClaimRevTreeRoot:    &merkletree.HashZero,
		IssuerClaimRootsTreeRoot:  &merkletree.HashZero,

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
		Value:                  utils.PrepareStrArray([]string{"10"}, 64),
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathNotExists:     "0",
		ProofType:              "0",
		ClaimPathKey:           "0",
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

func Test_RevokedClaimWithoutRevocationCheckMtp(t *testing.T) {
	desc := "User's claim revoked and the circuit not checking for revocation status (expected to fail)"
	fileName := "mtp/revoked_claim_without_revocation_check"

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

	requestID := big.NewInt(23)

	inputs := Inputs{
		RequestID:                       requestID.String(),
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
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

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 user.ID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		Value:                  utils.PrepareStrArray([]string{"10"}, 64),
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathKey:           "0",
		ClaimPathNotExists:     "0", // 0 for inclusion, 1 for non-inclusion
		ProofType:              "1",
		IssuerAuthState:        "0",
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

func Test_RevokedClaimWithoutRevocationCheckSig(t *testing.T) {
	desc := "User's claim revoked and the circuit not checking for revocation status"
	fileName := "sig/revoked_claim_without_revocation_check"
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
		Value:               utils.PrepareStrArray([]string{"10"}, 64),

		// additional mtp inputs
		IssuerClaimIdenState:      "0",
		IssuerClaimMtp:            utils.PrepareStrArray([]string{}, 40),
		IssuerClaimClaimsTreeRoot: &merkletree.HashZero,
		IssuerClaimRevTreeRoot:    &merkletree.HashZero,
		IssuerClaimRootsTreeRoot:  &merkletree.HashZero,

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
		Value:                  utils.PrepareStrArray([]string{"10"}, 64),
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathNotExists:     "0",
		ProofType:              "0",
		ClaimPathKey:           "0",
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

func Test_JSON_LD_Proof_non_inclusion(t *testing.T) {

	desc := "JSON-LD proof non inclusion. UserID = Subject. UserID out. User nonce = 0, " +
		"Subject nonce = 0 claim issued on userID (" +
		"Merklized claim)"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateJSONLD_NON_INCLUSIO_TestData(t, isUserIDProfile, isSubjectIDProfile, desc, "sig/jsonld_non_inclusion")
}

func Test_LinkID(t *testing.T) {
	desc := "LinkId not 0"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "6321", "sig/claimWithLinkNonce", Sig)
	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "6321", "mtp/claimWithLinkNonce", Mtp)
}

func Test_Nullify(t *testing.T) {
	desc := "Nullify modifier"
	isUserIDProfile := true
	isSubjectIDProfile := true
	value := utils.PrepareStrArray([]string{"94313"}, 64)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/nullify_modifier", utils.NULLIFY, &value, Sig)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/nullify_modifier", utils.NULLIFY, &value, Mtp)
}

func Test_Selective_Disclosure(t *testing.T) {
	desc := "Selective Disclosure modifier"
	isUserIDProfile := true
	isSubjectIDProfile := true
	value := utils.PrepareStrArray([]string{}, 64)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/selective_disclosure", utils.SD, &value, Sig)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/selective_disclosure", utils.SD, &value, Mtp)
}

func Test_Between(t *testing.T) {
	desc := "Between operator"
	isUserIDProfile := false
	isSubjectIDProfile := false
	value := utils.PrepareStrArray([]string{"8", "10"}, 64)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/between_operator", utils.BETWEEN, &value, Sig)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/between_operator", utils.BETWEEN, &value, Mtp)
}

func Test_Less_Than_Eq(t *testing.T) {
	desc := "LTE operator"
	isUserIDProfile := false
	isSubjectIDProfile := false
	value := utils.PrepareStrArray([]string{"10"}, 64)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "sig/less_than_eq_operator", utils.LTE, &value, Sig)
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, "0", "mtp/less_than_eq_operator", utils.LTE, &value, Mtp)
}

func generateTestData(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool,
	linkNonce string, fileName string, testType TestType) {
	generateTestDataWithOperator(t, desc, isUserIDProfile, isSubjectIDProfile, linkNonce, fileName, utils.EQ, nil, testType)
}

func generateTestDataWithOperator(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool,
	linkNonce string, fileName string, operator int, value *[]string, testType TestType) {
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

	var issuerClaimMtp, issuerAuthClaimMtp []string
	var issuerClaimClaimsTreeRoot, issuerClaimRevTreeRoot, issuerClaimRootsTreeRoot *merkletree.Hash
	var issuerClaimSignatureR8X, issuerClaimSignatureR8Y, issuerClaimSignatureS,
		issuerAuthClaimNonRevMtpAuxHi, issuerAuthClaimNonRevMtpAuxHv, issuerAuthClaimNonRevMtpNoAux,
		issuerClaimIdenState, proofType, issuerAuthClaimsTreeRoot,
		issuerAuthRevTreeRoot, issuerAuthRootsTreeRoot, issuerAuthState string
	var issuerAuthClaim *core.Claim
	var slotIndex int
	if testType == Sig {
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

		proofType = "0"
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
		proofType = "1"
	}

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	requestID := big.NewInt(23)

	linkID, err := utils.CalculateLinkID(linkNonce, claim)
	require.NoError(t, err)

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
		ClaimPathMtp:                    utils.PrepareStrArray([]string{}, 32),
		ClaimPathMtpNoAux:               "0",
		ClaimPathMtpAuxHi:               "0",
		ClaimPathMtpAuxHv:               "0",
		ClaimPathKey:                    "0",
		ClaimPathValue:                  "0",
		IsRevocationChecked:             1,
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

		LinkNonce: linkNonce,

		ProofType: proofType,
	}

	operatorOutput := "0"
	if operator == utils.NULLIFY {
		crs, ok := big.NewInt(0).SetString(valueInput[0], 10)
		require.True(t, ok)

		operatorOutput, err = utils.CalculateNullify(user.ID.BigInt(), nonceSubject, big.NewInt(10), crs)
		require.NoError(t, err)
	} else if operator == utils.SD {
		operatorOutput = big.NewInt(10).String()
	}

	out := Outputs{
		RequestID:              requestID.String(),
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuerClaimIdenState,
		IssuerClaimNonRevState: issuer.State(t).String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              strconv.Itoa(slotIndex),
		Operator:               operator,
		Value:                  valueInput,
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathKey:           "0",
		ClaimPathNotExists:     "0", // 0 for inclusion, 1 for non-inclusion
		ProofType:              proofType,
		IssuerAuthState:        issuerAuthState,
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

func generateJSONLDTestData(t *testing.T, desc string, isUserIDProfile, isSubjectIDProfile bool, fileName string, testType TestType) {
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

	var issuerClaimMtp, issuerAuthClaimMtp []string
	var issuerClaimClaimsTreeRoot, issuerClaimRevTreeRoot, issuerClaimRootsTreeRoot *merkletree.Hash
	var issuerClaimSignatureR8X, issuerClaimSignatureR8Y, issuerClaimSignatureS,
		issuerAuthClaimNonRevMtpAuxHi, issuerAuthClaimNonRevMtpAuxHv, issuerAuthClaimNonRevMtpNoAux,
		issuerClaimIdenState, proofType, issuerAuthClaimsTreeRoot,
		issuerAuthRevTreeRoot, issuerAuthRootsTreeRoot, issuerAuthState string
	var issuerAuthClaim *core.Claim
	var slotIndex int
	if testType == Sig {
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

		proofType = "0"
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

		slotIndex = 0
		proofType = "1"
	}

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	requestID := big.NewInt(23)

	inputs := Inputs{
		RequestID:                       requestID.String(),
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
		ClaimSubjectProfileNonce:        nonceSubject.String(),
		IssuerID:                        issuer.ID.BigInt().String(),
		IssuerClaim:                     claim,
		IssuerClaimMtp:                  issuerClaimMtp,
		IssuerClaimClaimsTreeRoot:       issuerClaimClaimsTreeRoot,
		IssuerClaimRevTreeRoot:          issuerClaimRevTreeRoot,
		IssuerClaimRootsTreeRoot:        issuerClaimRootsTreeRoot,
		IssuerClaimIdenState:            issuerClaimIdenState,
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
		SlotIndex:                       slotIndex,
		Timestamp:                       timestamp,
		Value:                           utils.PrepareStrArray([]string{valueKey.String()}, 64),

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

		LinkNonce: "0",

		ProofType: proofType,
	}

	out := Outputs{
		RequestID:              inputs.RequestID,
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuerClaimIdenState,
		IssuerClaimNonRevState: issuer.State(t).String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              strconv.Itoa(slotIndex),
		Operator:               utils.EQ,
		Value:                  utils.PrepareStrArray([]string{valueKey.String()}, 64),
		Timestamp:              timestamp,
		Merklized:              "1",
		ClaimPathKey:           pathKey.String(),
		ClaimPathNotExists:     "0", // 0 for inclusion, 1 for non-inclusion
		ProofType:              proofType,
		IssuerAuthState:        issuerAuthState,
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
		Value:                  utils.PrepareStrArray([]string{}, 64),
		Timestamp:              timestamp,
		Merklized:              "1",
		ClaimPathNotExists:     "1",
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
