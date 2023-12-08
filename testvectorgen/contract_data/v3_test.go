package contractdata

import (
	"context"
	"encoding/json"
	"math/big"
	"strconv"
	"testing"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/stretchr/testify/require"
	"test/utils"
)

const (
	ethAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
)

func Test_Generate_Test_CasesV3(t *testing.T) {

	issuerId, issuerFirstState := generateStateTransitionData(t, false, IssuerPK, UserPK, "Issuer from genesis state", "v3/issuer_genesis_state_v3", true)
	//userId, userFirstState := generateStateTransitionData(t, false, UserPK, IssuerPK, "User from genesis transition", "user_state_transition")

	//generateStateTransitionData(t, true, IssuerPK, UserPK, "Issuer next transition state", "issuer_next_state_transition")
	//generateStateTransitionData(t, true, UserPK, IssuerPK, "User next transition state", "user_next_state_transition")

	generateData(t, "BJJ: Issuer first state / user - genesis state", []*gistData{
		{issuerId, issuerFirstState},
	}, false, "v3/valid_bjj_user_genesis_v3", verifiable.BJJSignatureProofType, 1)
	//generateMTPData(t, "MTP: User non genesis but latest", []*gistData{
	//	{id, issuerFirstState},
	//	{nextId, userFirstState},
	//}, true, "valid_mtp_user_non_genesis", false)
	//generateMTPData(t, "MTP: User sign with address challenge genesis", []*gistData{
	//	{id, issuerFirstState},
	//	{nextId, userFirstState},
	//}, true, "valid_mtp_user_non_genesis_challenge_address", true)
	//
	//generateSigData(t, "Sig: Issuer first state", []*gistData{
	//	{id, issuerFirstState},
	//}, false, "valid_sig_user_genesis", false)
	//generateSigData(t, "Sig: User non genesis latest", []*gistData{
	//	{id, issuerFirstState},
	//	{nextId, userFirstState},
	//}, true, "valid_sig_user_non_genesis", false)
	//generateSigData(t, "Sig: User sign with address challenge genesis", []*gistData{
	//	{id, issuerFirstState},
	//	{nextId, userFirstState},
	//}, true, "valid_sig_user_non_genesis_challenge_address", true)

}

func generateData(t *testing.T, desc string, gistData []*gistData, nextState bool, fileName string, testProofType verifiable.ProofType, authEnabled int) {

	var linkNonce = "18"
	var nullifierSessionID string = "1234569"
	operator := utils.LT
	isRevocationChecked := 1 // checked
	isJSONLD := true         // merklized for now
	var err error

	const isRevoked = false
	const isSubjectIDProfile = true

	valueInput := utils.PrepareStrArray([]string{"20010101"}, 64)

	var user *utils.IdentityTest

	if authEnabled == 1 {
		user = utils.NewIdentity(t, UserPK)
	} else {
		// generate onchain identity
		user = utils.NewEthereumBasedIdentity(t, ethAddress)
	}
	issuer := utils.NewIdentity(t, IssuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)

	subjectID := user.ID

	var nonceSubject = new(big.Int)
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
	var slotIndex int

	if isJSONLD {
		mz, claim = utils.DefaultJSONNormalUserClaim(t, subjectID)
		path, err := merklize.NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject",
			"https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#birthday")
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
		slotIndex = 0

		//valueInput = utils.PrepareStrArray([]string{claimPathValue}, 64)
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
		slotIndex = 2
		pathKey = big.NewInt(0)
	}
	if nextState {
		_, claim1 := utils.DefaultJSONUserClaim(t, issuer.ID)
		user.AddClaim(t, claim1)
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
	if testProofType == verifiable.BJJSignatureProofType {
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

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 64)
	require.Nil(t, err)

	for _, data := range gistData {
		idPoseidonHash, _ := poseidon.Hash([]*big.Int{data.id})
		err = gisTree.Add(context.Background(), idPoseidonHash, data.state)
		require.Nil(t, err)
	}

	var authMTProof []string
	var challenge *big.Int
	var authNonRevMTProof []string
	var nodeAuxNonRev utils.NodeAuxValue
	var sig *babyjub.Signature
	var gistRoot *merkletree.Hash
	var gistProof []string
	var gistNodeAux utils.NodeAuxValue
	// user
	if authEnabled == 1 {
		challenge = big.NewInt(12345)
		authMTProof = user.AuthMTPStrign(t)
		authNonRevMTProof, nodeAuxNonRev = user.ClaimRevMTP(t, user.AuthClaim)
		sig = user.Sign(challenge)
		gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
		require.NoError(t, err)
		gistRoot = gisTree.Root()
		gistProof, gistNodeAux = utils.PrepareProof(gistProofRaw, utils.GistLevels)

	} else {

		emptyArr := make([]*merkletree.Hash, 0)
		authMTProof = utils.PrepareSiblingsStr(emptyArr, utils.IdentityTreeLevels)
		authNonRevMTProof = utils.PrepareSiblingsStr(emptyArr, utils.IdentityTreeLevels)
		nodeAuxNonRev = utils.NodeAuxValue{
			Key:   merkletree.HashZero.String(),
			Value: merkletree.HashZero.String(),
			NoAux: "0",
		}
		sig = &babyjub.Signature{
			R8: &babyjub.Point{
				X: new(big.Int),
				Y: new(big.Int),
			},
			S: new(big.Int),
		}

		gistRoot = &merkletree.HashZero
		gistProof = utils.PrepareSiblingsStr(emptyArr, utils.GistLevels)
		gistNodeAux = utils.NodeAuxValue{
			Key:   merkletree.HashZero.String(),
			Value: merkletree.HashZero.String(),
			NoAux: "0",
		}
	}

	inputs := Inputs{
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
		GistMtpAuxHi:                    gistNodeAux.Key,
		GistMtpAuxHv:                    gistNodeAux.Value,
		GistMtpNoAux:                    gistNodeAux.NoAux,
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
		ClaimSchema:                     "267831521922558027206082390043321796944",
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

		VerifierID:         "21929109382993718606847853573861987353620810345503358891473103689157378049",
		NullifierSessionID: nullifierSessionID,
		AuthEnabled:        authEnabled,
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
	if inputs.NullifierSessionID != "0" {
		claimSchema, ok := big.NewInt(0).SetString(inputs.ClaimSchema, 10)
		require.True(t, ok)

		verifierID, ok := big.NewInt(0).SetString(inputs.VerifierID, 10)
		require.True(t, ok)

		nullifierSessionID_, ok := big.NewInt(0).SetString(inputs.NullifierSessionID, 10)
		require.True(t, ok)

		nullifier, err = utils.CalculateNullify(
			user.ID.BigInt(),
			nonceSubject,
			claimSchema,
			verifierID,
			nullifierSessionID_,
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
		RequestID:              requestID,
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
		NullifierSessionID:     inputs.NullifierSessionID,
		Nullifier:              nullifier,
		AuthEnabled:            strconv.Itoa(authEnabled),
	}

	jsonData, err := json.Marshal(TestData{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonData))
}

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

	VerifierID         string `json:"verifierID"`
	NullifierSessionID string `json:"nullifierSessionID"`

	AuthEnabled int `json:"authEnabled"`
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
	NullifierSessionID     string `json:"nullifierSessionID"`
	OperatorOutput         string `json:"operatorOutput"`
	Nullifier              string `json:"nullifier"`
	AuthEnabled            string `json:"authEnabled"`
}

type TestData struct {
	Desc string  `json:"desc"`
	In   Inputs  `json:"inputs"`
	Out  Outputs `json:"expOut"`
}
