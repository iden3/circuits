package mtpv2onchain

import (
	"context"
	json2 "encoding/json"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
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
	requestID = "32"
)

type CredentialAtomicMTPOnChainV2Inputs struct {
	RequestID string `json:"requestID"`

	// begin  user data
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
	// end user data

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

type CredentialAtomicMTPOnChainV2Outputs struct {
	UserID                 string `json:"userID"`
	IssuerID               string `json:"issuerID"`
	IssuerClaimIdenState   string `json:"issuerClaimIdenState"`
	IssuerClaimNonRevState string `json:"issuerClaimNonRevState"`
	ClaimSchema            string `json:"claimSchema"`
	SlotIndex              string `json:"slotIndex"`
	Operator               int    `json:"operator"`
	ValueHash              string `json:"valueHash"`
	Timestamp              string `json:"timestamp"`
	Merklized              string `json:"merklized"`
	ClaimPathKey           string `json:"claimPathKey"`
	ClaimPathNotExists     string `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	GistRoot               string `json:"gistRoot"`
	Challenge              string `json:"challenge"`
}

type TestDataOnChainMTPV2 struct {
	Desc string                              `json:"desc"`
	In   CredentialAtomicMTPOnChainV2Inputs  `json:"inputs"`
	Out  CredentialAtomicMTPOnChainV2Outputs `json:"expOut"`
}

func Test_ClaimIssuedOnUserID(t *testing.T) {
	desc := "OnChain: User == Subject. Claim issued on UserID"
	isUserIDProfile := false
	isSubjectIDProfile := false
	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "claimIssuedOnUserID")
}

func Test_ClaimIssuedOnUserProfileID(t *testing.T) {
	desc := "OnChain: User != Subject. Claim issued on ProfileID"
	isUserIDProfile := false
	isSubjectIDProfile := true

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "claimIssuedOnProfileID")
}

func Test_ClaimIssuedOnUserProfileID2(t *testing.T) {
	desc := "OnChain: User == Subject. Claim issued on ProfileID"
	isUserIDProfile := true
	isSubjectIDProfile := true

	generateJSONLDTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "claimIssuedOnProfileID2")
}

func Test_ClaimNonMerklized(t *testing.T) {
	desc := "OnChain: User == Subject. Claim non merklized claim"
	isUserIDProfile := false
	isSubjectIDProfile := false

	generateTestData(t, desc, isUserIDProfile, isSubjectIDProfile, "claimNonMerklized")
}

func Test_RevokedClaimWithRevocationCheck(t *testing.T) {
	desc := "OnChain: User's claim revoked and the circuit checking for revocation status"
	fileName := "revoked_claim_with_revocation_check"

	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)

	nonceSubject := big.NewInt(0)

	claim := utils.DefaultUserClaim(t, user.ID)
	issuer.AddClaim(t, claim)

	revNonce := claim.GetRevocationNonce()
	revNonceBigInt := new(big.Int).SetUint64(revNonce)
	err := issuer.Ret.Add(context.Background(), revNonceBigInt, big.NewInt(0))
	require.NoError(t, err)
	issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)
	challenge := big.NewInt(12345)

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
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
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)
	inputs := CredentialAtomicMTPOnChainV2Inputs{
		RequestID:                       requestID,
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

	valuesHash, err := utils.PoseidonHash(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)

	out := CredentialAtomicMTPOnChainV2Outputs{
		UserID:                 user.ID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		ValueHash:              valuesHash.String(),
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathKey:           "0",
		ClaimPathNotExists:     "0", // 0 for inclusion, 1 for non-inclusion
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
	}

	json, err := json2.Marshal(TestDataOnChainMTPV2{
		Desc: desc,
		In:   inputs,
		Out:  out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func Test_RevokedClaimWithoutRevocationCheck(t *testing.T) {
	desc := "OnChain: Checking revoked status when claim is revoked onchain (MTP)"
	fileName := "revoked_claim_without_revocation_check"

	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

	nonce := big.NewInt(0)

	nonceSubject := big.NewInt(0)

	claim := utils.DefaultUserClaim(t, user.ID)
	issuer.AddClaim(t, claim)

	revNonce := claim.GetRevocationNonce()
	revNonceBigInt := new(big.Int).SetUint64(revNonce)
	err := issuer.Ret.Add(context.Background(), revNonceBigInt, big.NewInt(0))
	require.NoError(t, err)
	issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	challenge := big.NewInt(12345)

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
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
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	inputs := CredentialAtomicMTPOnChainV2Inputs{
		RequestID:                       requestID,
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
	valueHash, err := utils.PoseidonHash(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)

	out := CredentialAtomicMTPOnChainV2Outputs{
		UserID:                 user.ID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		ValueHash:              valueHash.String(),
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathKey:           "0",
		ClaimPathNotExists:     "0", // 0 for inclusion, 1 for non-inclusion
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
	}

	json, err := json2.Marshal(TestDataOnChainMTPV2{
		Desc: desc,
		In:   inputs,
		Out:  out,
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
	challenge := big.NewInt(12345)

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
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
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	inputs := CredentialAtomicMTPOnChainV2Inputs{
		RequestID:                       requestID,
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
	valueHash, err := utils.PoseidonHash(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)

	out := CredentialAtomicMTPOnChainV2Outputs{
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "0",
		Operator:               utils.EQ,
		ValueHash:              valueHash.String(),
		Timestamp:              timestamp,
		Merklized:              "1",
		ClaimPathKey:           pathKey.String(),
		ClaimPathNotExists:     "0", // 0 for inclusion, 1 for non-inclusion
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
	}

	json, err := json2.Marshal(TestDataOnChainMTPV2{
		Desc: desc,
		In:   inputs,
		Out:  out,
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

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
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
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	inputs := CredentialAtomicMTPOnChainV2Inputs{
		RequestID:                       requestID,
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
	valuesHash, err := utils.PoseidonHash(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)
	out := CredentialAtomicMTPOnChainV2Outputs{
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		ValueHash:              valuesHash.String(),
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathKey:           "0",
		ClaimPathNotExists:     "0",
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(), // 0 for inclusion, 1 for non-inclusion
	}

	json, err := json2.Marshal(TestDataOnChainMTPV2{
		Desc: desc,
		In:   inputs,
		Out:  out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
