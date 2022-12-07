package mtpv2

import (
	"context"
	json2 "encoding/json"
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

type CredentialAtomicMTPOffChainV2Inputs struct {
	// user data
	UserGenesisID            string `json:"userGenesisID"`            //
	Nonce                    string `json:"nonce"`                    //
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
}

type CredentialAtomicMTPOffChainV2Outputs struct {
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
}

type TestDataMTPV2 struct {
	Desc string                               `json:"desc"`
	In   CredentialAtomicMTPOffChainV2Inputs  `json:"inputs"`
	Out  CredentialAtomicMTPOffChainV2Outputs `json:"expOut"`
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

	inputs := CredentialAtomicMTPOffChainV2Inputs{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           nonce.String(),
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
	}

	out := CredentialAtomicMTPOffChainV2Outputs{
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
	}

	json, err := json2.Marshal(TestDataMTPV2{
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

	inputs := CredentialAtomicMTPOffChainV2Inputs{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           nonce.String(),
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
	}

	out := CredentialAtomicMTPOffChainV2Outputs{
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
	}

	json, err := json2.Marshal(TestDataMTPV2{
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

	claimJSONLDProof, claimJSONLDProofAux := utils.PrepareProof(jsonP)

	pathKey, err := path.MtEntry()
	require.NoError(t, err)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	inputs := CredentialAtomicMTPOffChainV2Inputs{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           nonce.String(),
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
	}

	out := CredentialAtomicMTPOffChainV2Outputs{
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "0",
		Operator:               utils.EQ,
		Value:                  utils.PrepareStrArray([]string{valueKey.String()}, 64),
		Timestamp:              timestamp,
		Merklized:              "1",
		ClaimPathKey:           pathKey.String(),
		ClaimPathNotExists:     "0", // 0 for inclusion, 1 for non-inclusion
	}

	json, err := json2.Marshal(TestDataMTPV2{
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

	inputs := CredentialAtomicMTPOffChainV2Inputs{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           nonce.String(),
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
	}

	out := CredentialAtomicMTPOffChainV2Outputs{
		UserID:                 userProfileID.BigInt().String(),
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
	}

	json, err := json2.Marshal(TestDataMTPV2{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
