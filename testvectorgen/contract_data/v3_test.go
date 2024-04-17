package contractdata

import (
	"context"
	"encoding/json"
	"math/big"
	"strconv"
	"testing"

	"test/utils"

	"github.com/ethereum/go-ethereum/common"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/stretchr/testify/require"
)

const (
	ethAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	UserPK     = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	IssuerPK   = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp  = "1642074362"
	requestID  = "32"
)

type StateTransitionInputs struct {
	AuthClaim               *core.Claim `json:"authClaim"`
	AuthClaimMtp            []string    `json:"authClaimMtp"`
	AuthClaimNonRevMtp      []string    `json:"authClaimNonRevMtp"`
	AuthClaimNonRevMtpAuxHi string      `json:"authClaimNonRevMtpAuxHi"`
	AuthClaimNonRevMtpAuxHv string      `json:"authClaimNonRevMtpAuxHv"`
	AuthClaimNonRevMtpNoAux string      `json:"authClaimNonRevMtpNoAux"`
	ClaimsTreeRoot          string      `json:"claimsTreeRoot"`
	IsOldStateGenesis       string      `json:"isOldStateGenesis"`
	NewUserState            string      `json:"newUserState"`
	OldUserState            string      `json:"oldUserState"`
	RevTreeRoot             string      `json:"revTreeRoot"`
	RootsTreeRoot           string      `json:"rootsTreeRoot"`
	SignatureR8X            string      `json:"signatureR8x"`
	SignatureR8Y            string      `json:"signatureR8y"`
	SignatureS              string      `json:"signatureS"`
	UserID                  string      `json:"userID"`
	NewAuthClaimMtp         []string    `json:"newAuthClaimMtp"`
	NewClaimsTreeRoot       string      `json:"newClaimsTreeRoot"`
	NewRevTreeRoot          string      `json:"newRevTreeRoot"`
	NewRootsTreeRoot        string      `json:"newRootsTreeRoot"`
}

type StateTransitionOutputs struct {
	ID                string `json:"userID"`
	NewUserState      string `json:"newUserState"`
	OldUserState      string `json:"oldUserState"`
	IsOldStateGenesis string `json:"isOldStateGenesis"`
}

type TestDataStateTransition struct {
	Desc string                 `json:"desc"`
	In   StateTransitionInputs  `json:"inputs"`
	Out  StateTransitionOutputs `json:"expOut"`
}

type gistData struct {
	id    *big.Int
	state *big.Int
}

func Test_Generate_Test_CasesV3(t *testing.T) {

	// genesis => first => second
	issuerId, issuerFirstState := generateStateTransitionData(t, false, IssuerPK, UserPK, "Issuer from genesis to first state transition", "v3/issuer_from_genesis_state_to_first_transition_v3", true, false)
	userId, userFirstState := generateStateTransitionData(t, false, UserPK, IssuerPK, "User from genesis transition", "v3/user_from_genesis_state_to_first_transition_v3", false, false)

	_, issuerSecondState := generateStateTransitionData(t, true, IssuerPK, UserPK, "Issuer from first to second transition", "v3/issuer_from_first_state_to_second_transition_v3", true, false)
	_, userSecondState := generateStateTransitionData(t, true, UserPK, IssuerPK, "User from first to second transition", "v3/user_from_first_state_to_second_transition_v3", false, false)

	_, issuerAuthDisabledFirstState := generateStateTransitionData(t, false, IssuerPK, UserPK, "Issuer from genesis to first state transition auth disabled", "v3/issuer_from_genesis_state_to_first_auth_disabled_transition_v3", false, true)

	generateData(t, "BJJ: Issuer first state / user - genesis state", []*gistData{
		{issuerId, issuerFirstState},
	}, false, false, false, false, "v3/valid_bjj_user_genesis_v3", verifiable.BJJSignatureProofType, 1)

	generateData(t, "BJJ: Issuer first state / user first state - valid proof", []*gistData{
		{issuerId, issuerFirstState},
		{userId, userFirstState},
	}, true, false, false, false, "v3/valid_bjj_user_first_v3", verifiable.BJJSignatureProofType, 1)

	generateData(t, "BJJ: Issuer second state / user first state - valid proof", []*gistData{
		{userId, userFirstState},
		{issuerId, issuerSecondState},
	}, true, false, false, true, "v3/valid_bjj_user_first_issuer_second_v3", verifiable.BJJSignatureProofType, 1)

	generateData(t, "BJJ: Issuer first state / user second state - valid proof", []*gistData{
		{userId, userSecondState},
		{issuerId, issuerSecondState},
	}, true, true, false, false, "v3/valid_bjj_user_second_issuer_first_v3", verifiable.BJJSignatureProofType, 1)

	generateData(t, "BJJ: Issuer first state / user - genesis state - Auth Disabled", []*gistData{
		{issuerId, issuerAuthDisabledFirstState},
	}, false, false, false, false, "v3/valid_bjj_user_genesis_auth_disabled_v3", verifiable.BJJSignatureProofType, 0)

	// MTP Data:
	generateData(t, "MTP: Issuer first state / user - genesis state", []*gistData{
		{issuerId, issuerFirstState},
	}, false, false, false, false, "v3/valid_mtp_user_genesis_v3", verifiable.Iden3SparseMerkleTreeProofType, 1)

	generateData(t, "MTP: Issuer first state / user first state - valid proof", []*gistData{
		{issuerId, issuerFirstState},
		{userId, userFirstState},
	}, true, false, false, false, "v3/valid_mtp_user_first_v3", verifiable.Iden3SparseMerkleTreeProofType, 1)

	generateData(t, "MTP: Issuer second state / user first state - valid proof", []*gistData{
		{userId, userFirstState},
		{issuerId, issuerSecondState},
	}, true, false, false, true, "v3/valid_mtp_user_first_issuer_second_v3", verifiable.Iden3SparseMerkleTreeProofType, 1)

	generateData(t, "MTP: Issuer first state / user second state - valid proof", []*gistData{
		{userId, userSecondState},
		{issuerId, issuerSecondState},
	}, true, true, false, false, "v3/valid_mtp_user_second_issuer_first_v3", verifiable.Iden3SparseMerkleTreeProofType, 1)

	generateData(t, "MTP: Issuer first state / user - genesis state - Auth Disabled", []*gistData{
		{issuerId, issuerAuthDisabledFirstState},
	}, false, false, false, false, "v3/valid_mtp_user_genesis_auth_disabled_v3", verifiable.Iden3SparseMerkleTreeProofType, 0)

	generateData(t, "BJJ: Issuer genesis state / user - first state", []*gistData{
		{userId, userFirstState},
	}, true, false, true, false, "v3/valid_bjj_user_first_issuer_genesis_v3", verifiable.BJJSignatureProofType, 1)
}

func generateStateTransitionData(t *testing.T, nextState bool, primaryPK, secondaryPK, desc, fileName string, isSubjectIDProfile bool, isEthBased bool) (*big.Int, *big.Int) {

	var err error
	primaryEntity := utils.NewIdentity(t, primaryPK)

	var secondaryEntity *utils.IdentityTest

	if !isEthBased {
		secondaryEntity = utils.NewIdentity(t, secondaryPK)
	} else {
		// generate onchain identity
		secondaryEntity = utils.NewEthereumBasedIdentity(t, ethAddress)
	}

	isGenesis := "1"
	// user
	authMTProof := primaryEntity.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := primaryEntity.ClaimRevMTP(t, primaryEntity.AuthClaim)

	oldState := primaryEntity.State(t) // old state is genesis
	oldCltRoot := primaryEntity.Clt.Root().BigInt().String()
	oldRevRoot := primaryEntity.Ret.Root().BigInt().String()
	oldRotRoot := primaryEntity.Rot.Root().BigInt().String()

	//if genesis == false {
	// extract pubKey

	subjectID := secondaryEntity.ID
	if isSubjectIDProfile {
		nonceSubject := big.NewInt(999)
		subjectID, err = core.ProfileID(secondaryEntity.ID, nonceSubject)
		require.NoError(t, err)
	}

	_, secondaryEntityClaim := utils.DefaultJSONNormalUserClaim(t, subjectID)
	primaryEntity.AddClaim(t, secondaryEntityClaim)

	if nextState {
		isGenesis = "0"
		// add claim just to change the state

		oldState = primaryEntity.State(t) // old state is genesis
		oldCltRoot = primaryEntity.Clt.Root().BigInt().String()
		oldRevRoot = primaryEntity.Ret.Root().BigInt().String()
		oldRotRoot = primaryEntity.Rot.Root().BigInt().String()
		authMTProof = primaryEntity.AuthMTPStrign(t)

		authNonRevMTProof, nodeAuxNonRev = primaryEntity.ClaimRevMTP(t, primaryEntity.AuthClaim)
		primaryEntityClaim := utils.DefaultUserClaim(t, primaryEntity.ID, nil)
		primaryEntity.AddClaim(t, primaryEntityClaim)
	}

	hashOldAndNewStates, err := poseidon.Hash(
		[]*big.Int{oldState, primaryEntity.State(t)})
	require.NoError(t, err)

	sig := primaryEntity.Sign(hashOldAndNewStates)
	require.NoError(t, err)

	newAuthMTProof := primaryEntity.AuthMTPStrign(t)
	newCltRoot := primaryEntity.Clt.Root().BigInt().String()
	newRevRoot := primaryEntity.Ret.Root().BigInt().String()
	newRotRoot := primaryEntity.Rot.Root().BigInt().String()

	inputs := StateTransitionInputs{
		AuthClaim:               primaryEntity.AuthClaim,
		AuthClaimMtp:            authMTProof,
		AuthClaimNonRevMtp:      authNonRevMTProof,
		AuthClaimNonRevMtpAuxHi: nodeAuxNonRev.Key,
		AuthClaimNonRevMtpAuxHv: nodeAuxNonRev.Value,
		AuthClaimNonRevMtpNoAux: nodeAuxNonRev.NoAux,
		ClaimsTreeRoot:          oldCltRoot,
		RevTreeRoot:             oldRevRoot,
		RootsTreeRoot:           oldRotRoot,
		IsOldStateGenesis:       isGenesis,
		NewUserState:            primaryEntity.State(t).String(),
		OldUserState:            oldState.String(),
		SignatureR8X:            sig.R8.X.String(),
		SignatureR8Y:            sig.R8.Y.String(),
		SignatureS:              sig.S.String(),
		UserID:                  primaryEntity.ID.BigInt().String(),
		NewAuthClaimMtp:         newAuthMTProof,
		NewClaimsTreeRoot:       newCltRoot,
		NewRevTreeRoot:          newRevRoot,
		NewRootsTreeRoot:        newRotRoot,
	}

	out := StateTransitionOutputs{
		ID:                primaryEntity.ID.BigInt().String(),
		NewUserState:      primaryEntity.State(t).String(),
		OldUserState:      oldState.String(),
		IsOldStateGenesis: isGenesis,
	}

	json_, err := json.Marshal(TestDataStateTransition{
		Desc: desc,
		In:   inputs,
		Out:  out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json_))

	return primaryEntity.ID.BigInt(), primaryEntity.State(t)
}

func generateData(t *testing.T, desc string, gistData []*gistData, userFirstState bool, userSecondState bool, issuetGenesisState bool, issuerSecondState bool, fileName string, testProofType verifiable.ProofType, isBJJAuthEnabled int) {

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

	if isBJJAuthEnabled == 1 {
		user = utils.NewIdentity(t, UserPK)
	} else {
		// generate onchain identity
		user = utils.NewEthereumBasedIdentity(t, ethAddress)
		nullifierSessionID = "0"
	}
	issuer := utils.NewIdentity(t, IssuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)

	subjectID := user.ID

	var nonceSubject = new(big.Int)
	if isSubjectIDProfile && isBJJAuthEnabled == 1 {
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
		claim = utils.DefaultUserClaim(t, subjectID, nil)
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

	if userFirstState {
		_, claim1 := utils.DefaultJSONNormalUserClaim(t, issuer.ID)
		user.AddClaim(t, claim1)

		if userSecondState {
			claim2 := utils.DefaultUserClaim(t, user.ID, nil)
			user.AddClaim(t, claim2)
		}
	}

	if isRevoked {
		revNonce := claim.GetRevocationNonce()
		revNonceBigInt := new(big.Int).SetUint64(revNonce)
		issuer.Ret.Add(context.Background(), revNonceBigInt, big.NewInt(0))
	}

	var issuerClaimMtp, issuerAuthClaimMtp, issuerAuthClaimNonRevMtp []string
	var issuerClaimClaimsTreeRoot, issuerClaimRevTreeRoot, issuerClaimRootsTreeRoot *merkletree.Hash
	var issuerClaimSignatureR8X, issuerClaimSignatureR8Y, issuerClaimSignatureS,
		issuerAuthClaimNonRevMtpAuxHi, issuerAuthClaimNonRevMtpAuxHv, issuerAuthClaimNonRevMtpNoAux,
		issuerClaimIdenState, proofType string

	var issuerAuthClaimsTreeRoot, issuerAuthRevTreeRoot, issuerAuthRootsTreeRoot string
	var issuerAuthState string
	var issuerAuthClaim *core.Claim

	issuerAuthClaimsTreeRoot = issuer.Clt.Root().BigInt().String()
	issuerAuthRevTreeRoot = issuer.Ret.Root().BigInt().String()
	issuerAuthRootsTreeRoot = issuer.Rot.Root().BigInt().String()

	issuerAuthState = issuer.State(t).String()

	issuerAuthClaimMtp, _ = issuer.ClaimMTP(t, issuer.AuthClaim)

	if !issuetGenesisState {
		issuer.AddClaim(t, claim)
	}

	issuerClaimMtp, _ = issuer.ClaimMTP(t, claim)
	require.NoError(t, err)
	issuerClaimIdenState = issuer.State(t).String()

	issuerClaimClaimsTreeRoot = issuer.Clt.Root()
	issuerClaimRevTreeRoot = issuer.Ret.Root()
	issuerClaimRootsTreeRoot = issuer.Rot.Root()

	// add another claim to issuer if it is a second state
	if issuerSecondState {
		primaryEntityClaim := utils.DefaultUserClaim(t, issuer.ID, nil)
		issuer.AddClaim(t, primaryEntityClaim)
	}

	// prove revocation on latest state of the issuer
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	issuerAuthClaimNonRevMtp, issuerAuthClaimNodeAux := issuer.ClaimRevMTP(t, issuer.AuthClaim)
	issuerAuthClaimNonRevMtpNoAux = issuerAuthClaimNodeAux.NoAux
	issuerAuthClaimNonRevMtpAuxHi = issuerAuthClaimNodeAux.Key
	issuerAuthClaimNonRevMtpAuxHv = issuerAuthClaimNodeAux.Value

	if testProofType == verifiable.BJJSignatureProofType {
		// Sig claim
		claimSig := issuer.SignClaim(t, claim)

		issuerClaimSignatureR8X = claimSig.R8.X.String()
		issuerClaimSignatureR8Y = claimSig.R8.Y.String()
		issuerClaimSignatureS = claimSig.S.String()

		issuerAuthClaim = issuer.AuthClaim

		proofType = "1"
	} else {

		issuerClaimSignatureR8X = "0"
		issuerClaimSignatureR8Y = "0"
		issuerClaimSignatureS = "0"

		issuerAuthClaimNonRevMtpAuxHi = "0"
		issuerAuthClaimNonRevMtpAuxHv = "0"
		issuerAuthClaimNonRevMtpNoAux = "0"

		issuerAuthClaimMtp = utils.PrepareStrArray([]string{}, 40)

		issuerAuthClaim = &core.Claim{}

		issuerAuthClaimsTreeRoot = (&merkletree.HashZero).BigInt().String()
		issuerAuthRevTreeRoot = (&merkletree.HashZero).BigInt().String()
		issuerAuthRootsTreeRoot = (&merkletree.HashZero).BigInt().String()

		issuerAuthState = "0"

		slotIndex = 2
		proofType = "2"
	}

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 64)
	require.Nil(t, err)

	for _, data := range gistData {
		idPoseidonHash, _ := poseidon.Hash([]*big.Int{data.id})
		err = gisTree.Add(context.Background(), idPoseidonHash, data.state)
		require.Nil(t, err)
	}

	var authMTProof []string
	var challenge *big.Int
	var userAuthNonRevMTProof []string
	var userNodeAuxNonRev utils.NodeAuxValue
	var sig *babyjub.Signature
	var gistRoot *merkletree.Hash
	var gistProof []string
	var gistNodeAux utils.NodeAuxValue

	addr := common.HexToAddress(ethAddress)
	challenge = new(big.Int).SetBytes(merkletree.SwapEndianness(addr.Bytes()))

	// user
	if isBJJAuthEnabled == 1 {
		authMTProof = user.AuthMTPStrign(t)
		userAuthNonRevMTProof, userNodeAuxNonRev = user.ClaimRevMTP(t, user.AuthClaim)
		sig = user.Sign(challenge)
		gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
		require.NoError(t, err)
		gistRoot = gisTree.Root()
		gistProof, gistNodeAux = utils.PrepareProof(gistProofRaw, utils.GistLevels)

	} else {

		emptyArr := make([]*merkletree.Hash, 0)
		authMTProof = utils.PrepareSiblingsStr(emptyArr, utils.IdentityTreeLevels)
		userAuthNonRevMTProof = utils.PrepareSiblingsStr(emptyArr, utils.IdentityTreeLevels)
		userNodeAuxNonRev = utils.NodeAuxValue{
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

		user.AuthClaim = &core.Claim{}
	}
	t.Log(issuer.State(t).String())
	valueArraySize := utils.GetValueArraySizeForOperator(operator)

	inputs := Inputs{
		RequestID:                       requestID,
		UserGenesisID:                   user.ID.BigInt().String(),
		ProfileNonce:                    nonce.String(),
		UserAuthClaim:                   user.AuthClaim,
		UserAuthClaimMtp:                authMTProof,
		UserAuthClaimNonRevMtp:          userAuthNonRevMTProof,
		UserAuthClaimNonRevMtpAuxHi:     userNodeAuxNonRev.Key,
		UserAuthClaimNonRevMtpAuxHv:     userNodeAuxNonRev.Value,
		UserAuthClaimNonRevMtpNoAux:     userNodeAuxNonRev.NoAux,
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
		ValueArraySize:                  valueArraySize,
		IssuerClaimSignatureR8X:         issuerClaimSignatureR8X,
		IssuerClaimSignatureR8Y:         issuerClaimSignatureR8Y,
		IssuerClaimSignatureS:           issuerClaimSignatureS,
		IssuerAuthClaim:                 issuerAuthClaim,
		IssuerAuthClaimMtp:              issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:        issuerAuthClaimNonRevMtp,
		IssuerAuthClaimNonRevMtpAuxHi:   issuerAuthClaimNonRevMtpAuxHi,
		IssuerAuthClaimNonRevMtpAuxHv:   issuerAuthClaimNonRevMtpAuxHv,
		IssuerAuthClaimNonRevMtpNoAux:   issuerAuthClaimNonRevMtpNoAux,
		IssuerAuthClaimsTreeRoot:        issuerAuthClaimsTreeRoot,
		IssuerAuthRevTreeRoot:           issuerAuthRevTreeRoot,
		IssuerAuthRootsTreeRoot:         issuerAuthRootsTreeRoot,
		IssuerAuthState:                 issuerAuthState,

		LinkNonce: linkNonce,

		ProofType: proofType,

		VerifierID:         "21929109382993718606847853573861987353620810345503358891473103689157378049",
		NullifierSessionID: nullifierSessionID,
		IsBJJAuthEnabled:   isBJJAuthEnabled,
	}

	valuesHash, err := utils.PoseidonHashValue(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)
	claimSchemaInt, ok := big.NewInt(0).SetString(inputs.ClaimSchema, 10)
	require.True(t, ok)

	linkID, err := utils.CalculateLinkID(linkNonce, claim)
	require.NoError(t, err)

	operatorOutput := "0"
	nullifier := "0"
	verifierID, ok := big.NewInt(0).SetString(inputs.VerifierID, 10)
	require.True(t, ok)
	nullifierSessionID_, ok := big.NewInt(0).SetString(inputs.NullifierSessionID, 10)
	require.True(t, ok)
	if inputs.NullifierSessionID != "0" {
		claimSchema, ok := big.NewInt(0).SetString(inputs.ClaimSchema, 10)
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
	merklizedBigInt, ok := big.NewInt(0).SetString(merklized, 10)

	firstPartQueryHash, err := poseidon.Hash([]*big.Int{
		claimSchemaInt,
		big.NewInt(int64(inputs.SlotIndex)),
		big.NewInt(int64(inputs.Operator)),
		pathKey,
		merklizedBigInt,
		valuesHash,
	})
	require.NoError(t, err)
	require.True(t, ok)
	circuitQueryHash, err := poseidon.Hash([]*big.Int{
		firstPartQueryHash,
		big.NewInt(int64(valueArraySize)),
		big.NewInt(int64(isRevocationChecked)),
		verifierID,
		nullifierSessionID_,
		new(big.Int),
	})
	require.NoError(t, err)

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
		ProofType:              proofType,
		IssuerState:            issuerState,
		LinkID:                 linkID,
		OperatorOutput:         operatorOutput,
		Nullifier:              nullifier,
		IsBJJAuthEnabled:       strconv.Itoa(isBJJAuthEnabled),
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
	ClaimPathMtp      []string `json:"claimPathMtp"`
	ClaimPathMtpNoAux string   `json:"claimPathMtpNoAux"` // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi string   `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv string   `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathValue    string   `json:"claimPathValue"`    // value in this path in merklized json-ld document
	ClaimPathKey      string   `json:"claimPathKey"`      // hash of path in merklized json-ld document

	Operator       int      `json:"operator"`
	SlotIndex      int      `json:"slotIndex"`
	Timestamp      string   `json:"timestamp"`
	Value          []string `json:"value"`
	ValueArraySize int      `json:"valueArraySize"`

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

	IsBJJAuthEnabled int `json:"isBJJAuthEnabled"`
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
	Challenge              string `json:"challenge"`
	IssuerState            string `json:"issuerState"`
	LinkID                 string `json:"linkID"`
	OperatorOutput         string `json:"operatorOutput"`
	Nullifier              string `json:"nullifier"`
	IsBJJAuthEnabled       string `json:"isBJJAuthEnabled"`
}

type TestData struct {
	Desc string  `json:"desc"`
	In   Inputs  `json:"inputs"`
	Out  Outputs `json:"expOut"`
}
