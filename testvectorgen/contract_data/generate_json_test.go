package contractdata

import (
	"context"
	json2 "encoding/json"
	"math/big"
	"testing"

	"test/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/stretchr/testify/require"
)

const (
	UserPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	IssuerPK  = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
)

func Test_Generate_Test_Cases(t *testing.T) {

	id, state := generateStateTransitionData(t, false, IssuerPK, UserPK, "Issuer from genesis state", "issuer_genesis_state")
	generateStateTransitionData(t, true, IssuerPK, UserPK, "Issuer next transition state", "issuer_next_state_transition")
	generateMTPData(t, "MTP: Issuer genesis", id, state, false, "valid_mtp_user_genesis", false)

	nextId, nextState := generateStateTransitionData(t, false, UserPK, IssuerPK, "User from genesis transition", "user_state_transition")
	generateMTPData(t, "MTP: User genesis", nextId, nextState, true, "valid_mtp_user_non_genesis", false)
	generateMTPData(t, "MTP: User sign with address challenge genesis", nextId, nextState, true, "valid_mtp_user_non_genesis_challenge_address", true)
}

func generateStateTransitionData(t *testing.T, nextState bool, primaryPK, secondaryPK, desc, fileName string) (*big.Int, *big.Int) {

	primaryEntity := utils.NewIdentity(t, primaryPK)
	secondaryEntity := utils.NewIdentity(t, secondaryPK)

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

	secondaryEntityClaim := utils.DefaultUserClaim(t, secondaryEntity.ID)
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
		primaryEntityClaim := utils.DefaultUserClaim(t, primaryEntity.ID)
		primaryEntity.AddClaim(t, primaryEntityClaim)
	}

	hashOldAndNewStates, err := poseidon.Hash(
		[]*big.Int{oldState, primaryEntity.State(t)})
	require.NoError(t, err)

	sig := primaryEntity.Sign(hashOldAndNewStates)
	require.NoError(t, err)

	inputs := utils.StateTransitionInputs{
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
	}

	out := utils.StateTransitionOutputs{
		ID:                primaryEntity.ID.BigInt().String(),
		NewUserState:      primaryEntity.State(t).String(),
		OldUserState:      oldState.String(),
		IsOldStateGenesis: isGenesis,
	}

	json, err := json2.Marshal(utils.TestDataStateTransition{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))

	return primaryEntity.ID.BigInt(), primaryEntity.State(t)
}

func generateMTPData(t *testing.T, desc string, id, newState *big.Int, nextState bool, fileName string, isAddressChallenge bool) {
	var err error

	user := utils.NewIdentity(t, UserPK)
	issuer := utils.NewIdentity(t, IssuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)

	subjectID := user.ID
	nonceSubject := big.NewInt(0)

	claim := utils.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)
	require.NoError(t, err)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)
	challenge := big.NewInt(12345)
	if isAddressChallenge {
		addr := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
		challenge = new(big.Int).SetBytes(merkletree.SwapEndianness(addr.Bytes()))
	}

	if nextState {
		claim1 := utils.DefaultUserClaim(t, issuer.ID)
		user.AddClaim(t, claim1)
	}

	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	require.Nil(t, err)
	idPoseidonHash, _ := poseidon.Hash([]*big.Int{id})

	err = gisTree.Add(context.Background(), idPoseidonHash, newState)
	require.NoError(t, err)
	// user
	authMTProof := user.AuthMTPStrign(t)

	authNonRevMTProof, nodeAuxNonRev := user.ClaimRevMTP(t, user.AuthClaim)

	sig := user.Sign(challenge)

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	require.NoError(t, err)

	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	inputs := utils.CredentialAtomicMTPOnChainV2Inputs{
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
	out := utils.CredentialAtomicMTPOnChainV2Outputs{
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

	json, err := json2.Marshal(utils.TestDataStateTransition{
		Desc: desc,
		In:   inputs,
		Out:  out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
