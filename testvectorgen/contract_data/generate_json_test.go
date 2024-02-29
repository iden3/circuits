package contractdata

import (
	"context"
	json2 "encoding/json"
	"math/big"
	"testing"

	"test/utils"

	"github.com/ethereum/go-ethereum/common"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/stretchr/testify/require"
)

const (
	UserPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	IssuerPK  = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
	requestID = "32"
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
	Merklized              string `json:"merklized"`
	UserID                 string `json:"userID"`
	CircuitQueryHash       string `json:"circuitQueryHash"`
	RequestID              string `json:"requestID"`
	IssuerID               string `json:"issuerID"`
	IssuerClaimIdenState   string `json:"issuerClaimIdenState"`
	IssuerClaimNonRevState string `json:"issuerClaimNonRevState"`
	Timestamp              string `json:"timestamp"`
	IsRevocationChecked    string `json:"isRevocationChecked"`
	GistRoot               string `json:"gistRoot"`
	Challenge              string `json:"challenge"`
}
type TestDataStateTransition struct {
	Desc string                 `json:"desc"`
	In   StateTransitionInputs  `json:"inputs"`
	Out  StateTransitionOutputs `json:"expOut"`
}

type TestDataOnChainMTPV2 struct {
	Desc string                              `json:"desc"`
	In   CredentialAtomicMTPOnChainV2Inputs  `json:"inputs"`
	Out  CredentialAtomicMTPOnChainV2Outputs `json:"expOut"`
}

type CredentialAtomicSigOnChainV2Inputs struct {
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
}

type CredentialAtomicSigOnChainV2Outputs struct {
	Merklized              string `json:"merklized"`
	UserID                 string `json:"userID"`
	CircuitQueryHash       string `json:"circuitQueryHash"`
	IssuerAuthState        string `json:"issuerAuthState"`
	RequestID              string `json:"requestID"`
	IssuerID               string `json:"issuerID"`
	IssuerClaimNonRevState string `json:"issuerClaimNonRevState"`
	Timestamp              string `json:"timestamp"`
	IsRevocationChecked    string `json:"isRevocationChecked"`
	Challenge              string `json:"challenge"`
	GistRoot               string `json:"gistRoot"`
}
type TestDataSigV2 struct {
	Desc string                              `json:"desc"`
	In   CredentialAtomicSigOnChainV2Inputs  `json:"inputs"`
	Out  CredentialAtomicSigOnChainV2Outputs `json:"expOut"`
}

func Test_Generate_Test_Cases(t *testing.T) {

	id, issuerFirstState := generateStateTransitionData(t, false, IssuerPK, UserPK, "Issuer from genesis state", "issuer_genesis_state", false, false)
	nextId, userFirstState := generateStateTransitionData(t, false, UserPK, IssuerPK, "User from genesis transition", "user_state_transition", false, false)

	generateStateTransitionData(t, true, IssuerPK, UserPK, "Issuer next transition state", "issuer_next_state_transition", false, false)
	generateStateTransitionData(t, true, UserPK, IssuerPK, "User next transition state", "user_next_state_transition", false, false)

	generateMTPData(t, "MTP: Issuer first state", []*gistData{
		{id, issuerFirstState},
	}, false, "valid_mtp_user_genesis", false)
	generateMTPData(t, "MTP: User non genesis but latest", []*gistData{
		{id, issuerFirstState},
		{nextId, userFirstState},
	}, true, "valid_mtp_user_non_genesis", false)
	generateMTPData(t, "MTP: User sign with address challenge genesis", []*gistData{
		{id, issuerFirstState},
		{nextId, userFirstState},
	}, true, "valid_mtp_user_non_genesis_challenge_address", true)

	generateSigData(t, "Sig: Issuer first state", []*gistData{
		{id, issuerFirstState},
	}, false, "valid_sig_user_genesis", false)
	generateSigData(t, "Sig: User non genesis latest", []*gistData{
		{id, issuerFirstState},
		{nextId, userFirstState},
	}, true, "valid_sig_user_non_genesis", false)
	generateSigData(t, "Sig: User sign with address challenge genesis", []*gistData{
		{id, issuerFirstState},
		{nextId, userFirstState},
	}, true, "valid_sig_user_non_genesis_challenge_address", true)

}

type gistData struct {
	id    *big.Int
	state *big.Int
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

	json, err := json2.Marshal(TestDataStateTransition{
		Desc: desc,
		In:   inputs,
		Out:  out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))

	return primaryEntity.ID.BigInt(), primaryEntity.State(t)
}

func generateMTPData(t *testing.T, desc string, gistData []*gistData, nextState bool, fileName string, isAddressChallenge bool) {

	var err error

	user := utils.NewIdentity(t, UserPK)
	issuer := utils.NewIdentity(t, IssuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)

	subjectID := user.ID
	nonceSubject := big.NewInt(0)

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
	if isAddressChallenge {
		addr := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
		challenge = new(big.Int).SetBytes(merkletree.SwapEndianness(addr.Bytes()))
	}

	if nextState {
		_, claim1 := utils.DefaultJSONUserClaim(t, issuer.ID)
		user.AddClaim(t, claim1)
	}

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 64)
	require.Nil(t, err)

	for _, data := range gistData {
		idPoseidonHash, _ := poseidon.Hash([]*big.Int{data.id})
		err = gisTree.Add(context.Background(), idPoseidonHash, data.state)
		require.Nil(t, err)
	}

	// user
	authMTProof := user.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := user.ClaimRevMTP(t, user.AuthClaim)

	sig := user.Sign(challenge)

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	require.NoError(t, err)

	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw, utils.GistLevels)

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
		IsRevocationChecked:             1,
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

	out := CredentialAtomicMTPOnChainV2Outputs{
		RequestID:              requestID,
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerClaimIdenState:   issuer.State(t).String(),
		IssuerClaimNonRevState: issuer.State(t).String(),
		CircuitQueryHash:       circuitQueryHash.String(),
		Timestamp:              timestamp,
		Merklized:              "1",
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
		IsRevocationChecked:    "1",
	}

	json, err := json2.Marshal(TestDataOnChainMTPV2{
		Desc: desc,
		In:   inputs,
		Out:  out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}

func generateSigData(t *testing.T, desc string, gistData []*gistData, nextState bool, fileName string, isAddressChallenge bool) {

	var err error

	user := utils.NewIdentity(t, UserPK)
	issuer := utils.NewIdentity(t, IssuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)

	subjectID := user.ID
	nonceSubject := big.NewInt(0)

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
	if isAddressChallenge {
		addr := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
		challenge = new(big.Int).SetBytes(merkletree.SwapEndianness(addr.Bytes()))
	}

	if nextState {
		_, claim1 := utils.DefaultJSONUserClaim(t, issuer.ID)
		user.AddClaim(t, claim1)
	}

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 64)
	require.Nil(t, err)

	for _, data := range gistData {
		idPoseidonHash, _ := poseidon.Hash([]*big.Int{data.id})
		err = gisTree.Add(context.Background(), idPoseidonHash, data.state)
		require.Nil(t, err)
	}
	// user
	authMTProof := user.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := user.ClaimRevMTP(t, user.AuthClaim)

	sig := user.Sign(challenge)

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	require.NoError(t, err)

	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw, utils.GistLevels)

	inputs := CredentialAtomicSigOnChainV2Inputs{
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
		SlotIndex:           0,
		Timestamp:           timestamp,
		IsRevocationChecked: 1,
		Value: []string{valueKey.String(), "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
			"0", "0",
			"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
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

	out := CredentialAtomicSigOnChainV2Outputs{
		RequestID:              requestID,
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		Timestamp:              timestamp,
		Merklized:              "1",
		CircuitQueryHash:       circuitQueryHash.String(),
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
		IsRevocationChecked:    "1",
	}

	json, err := json2.Marshal(TestDataSigV2{
		Desc: desc,
		In:   inputs,
		Out:  out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
