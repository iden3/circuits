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
	requestID = "32"
)

func Test_Generate_Test_Cases(t *testing.T) {

	id, state := generateStateTransitionData(t, false, IssuerPK, UserPK, "Issuer from genesis state", "issuer_genesis_state")
	nextId, nextState := generateStateTransitionData(t, false, UserPK, IssuerPK, "User from genesis transition", "user_state_transition")

	generateStateTransitionData(t, true, IssuerPK, UserPK, "Issuer next transition state", "issuer_next_state_transition")

	generateMTPData(t, "MTP: Issuer genesis", []*gistData{
		{id, state},
	}, false, "valid_mtp_user_genesis", false)
	// snap, _ := mtpTree.()(context.Background(), mtpTree.Root())
	generateMTPData(t, "MTP: User genesis", []*gistData{
		{id, state},
		{nextId, nextState},
	}, true, "valid_mtp_user_non_genesis", false)
	generateMTPData(t, "MTP: User sign with address challenge genesis", []*gistData{
		{id, state},
		{nextId, nextState},
	}, true, "valid_mtp_user_non_genesis_challenge_address", true)

	generateSigData(t, "Sig: Issuer genesis", []*gistData{
		{id, state},
	}, false, "valid_sig_user_genesis", false)
	generateSigData(t, "Sig: User genesis", []*gistData{
		{id, state},
		{nextId, nextState},
	}, true, "valid_sig_user_non_genesis", false)
	generateSigData(t, "Sig: User sign with address challenge genesis", []*gistData{
		{id, state},
		{nextId, nextState},
	}, true, "valid_sig_user_non_genesis_challenge_address", true)

}

type gistData struct {
	id    *big.Int
	state *big.Int
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
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	inputs := utils.CredentialAtomicMTPOnChainV2Inputs{
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

	json, err := json2.Marshal(utils.TestDataOnChainMTPV2{
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

	claim := utils.DefaultUserClaim(t, subjectID)

	// Sig claim
	claimSig := issuer.SignClaim(t, claim)

	issuerClaimNonRevState := issuer.State(t)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux := issuer.ClaimRevMTP(t, issuer.AuthClaim)

	emptyPathMtp := utils.PrepareSiblingsStr([]*merkletree.Hash{&merkletree.HashZero}, 32)

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
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	inputs := utils.CredentialAtomicSigOnChainV2Inputs{
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
	}

	issuerAuthState := issuer.State(t)

	valuesHash, err := utils.PoseidonHash(utils.FromStringArrayToBigIntArray(inputs.Value))
	require.NoError(t, err)
	out := utils.CredentialAtomicSigOnChainV2Outputs{
		UserID:                 userProfileID.BigInt().String(),
		IssuerID:               issuer.ID.BigInt().String(),
		IssuerAuthState:        issuerAuthState.String(),
		IssuerClaimNonRevState: issuerClaimNonRevState.String(),
		ClaimSchema:            "180410020913331409885634153623124536270",
		SlotIndex:              "2",
		Operator:               utils.EQ,
		Timestamp:              timestamp,
		Merklized:              "0",
		ClaimPathNotExists:     "0",
		ValueHash:              valuesHash.String(),
		Challenge:              challenge.String(),
		GistRoot:               gistRoot.BigInt().String(),
	}

	json, err := json2.Marshal(utils.TestDataSigV2{
		Desc: desc,
		In:   inputs,
		Out:  out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(json))
}
