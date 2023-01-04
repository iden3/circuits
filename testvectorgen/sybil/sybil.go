package sybil

import (
	"context"
	"encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/stretchr/testify/require"
	"math/big"
	"test/utils"
	"testing"
)

func generateTestDataMTP(t *testing.T, desc, fileName string, invalidGist, invalidIdentity, isUserIDProfile, isSubjectIDProfile bool) {
	var err error

	user := utils.NewIdentity(t, mtpUserPK)
	issuer := utils.NewIdentity(t, mtpIssuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)
	if isUserIDProfile {
		nonce = big.NewInt(10)
		userProfileID, err = core.ProfileID(user.ID, nonce)
		require.NoError(t, err)
	}

	expectedSybilID := "8903332384851738260747517773325377528299199208576629685986891704182978270332"
	subjectID := user.ID
	nonceSubject := big.NewInt(0)
	if isSubjectIDProfile {
		nonceSubject = big.NewInt(999)
		subjectID, err = core.ProfileID(user.ID, nonceSubject)
		require.NoError(t, err)
		expectedSybilID = "15928283987833756851644249157457264609084917385190027282640632960343512336427"
	}

	// unique claim
	uniClaim := utils.DefaultUserClaim(t, subjectID)
	issuer.AddClaim(t, uniClaim)
	issuerClaimMtp, _ := issuer.ClaimMTP(t, uniClaim)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, uniClaim)

	secret := big.NewInt(10)
	scClaim := utils.GenerateNewStateCommitmentClaim(t, secret)
	user.AddClaim(t, scClaim)
	userClaimMtp, _ := user.ClaimMTP(t, scClaim)

	// gist
	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	require.Nil(t, err)
	err = gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
	require.Nil(t, err)

	err = gisTree.Add(context.Background(), user.IDHash(t), user.State(t))
	require.Nil(t, err)

	if invalidGist {
		gisTree, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
		require.Nil(t, err)
		err = gisTree.Add(context.Background(), big.NewInt(3), big.NewInt(3))
		require.Nil(t, err)

		err = gisTree.Add(context.Background(), big.NewInt(4), big.NewInt(4))
		require.Nil(t, err)

		err = gisTree.Add(context.Background(), big.NewInt(5), big.NewInt(5))
		require.Nil(t, err)
	}

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	if invalidIdentity {
		sk := babyjub.NewRandPrivKey()
		skB := sk.Scalar().BigInt().Bytes()
		user = utils.NewIdentity(t, fmt.Sprintf("%x", skB))
	}

	inputs := InputsMTP{
		IssuerClaim:           uniClaim,
		IssuerClaimMtp:        issuerClaimMtp,
		IssuerClaimClaimsRoot: issuer.Clt.Root(),
		IssuerClaimRevRoot:    issuer.Ret.Root(),
		IssuerClaimRootsRoot:  issuer.Rot.Root(),
		IssuerClaimIdenState:  issuer.State(t).String(),

		IssuerClaimNonRevMtp:      issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi: issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv: issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux: issuerClaimNonRevAux.NoAux,

		IssuerClaimNonRevClaimsRoot: issuer.Clt.Root(),
		IssuerClaimNonRevRevRoot:    issuer.Ret.Root(),
		IssuerClaimNonRevRootsRoot:  issuer.Rot.Root(),
		IssuerClaimNonRevState:      issuer.State(t).String(),

		IssuerClaimSchema: "180410020913331409885634153623124536270",

		StateCommitmentClaim:           scClaim,
		StateCommitmentClaimMtp:        userClaimMtp,
		StateCommitmentClaimClaimsRoot: user.Clt.Root(),
		StateCommitmentClaimRevRoot:    user.Ret.Root(),
		StateCommitmentClaimRootsRoot:  user.Rot.Root(),
		StateCommitmentClaimIdenState:  user.State(t).String(),

		GistRoot:     gistRoot,
		GistMtp:      gistProof,
		GistMtpAuxHi: gistNodAux.Key,
		GistMtpAuxHv: gistNodAux.Value,
		GistMtpNoAux: gistNodAux.NoAux,

		CRS: big.NewInt(123456789).String(),

		UserGenesisID:            user.ID.BigInt().String(),
		ProfileNonce:             nonce.String(),
		ClaimSubjectProfileNonce: nonceSubject.String(),

		IssuerID:  "123",
		RequestID: "321",
		Timestamp: timestamp,
	}

	out := OutputsMTP{
		UserID:  userProfileID.BigInt().String(),
		SybilID: expectedSybilID,
	}

	jsonTestData, err := json.Marshal(TestDataMTP{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonTestData))
}

func generateTestDataSig(t *testing.T, desc, fileName string, invalidGist, invalidIdentity, isUserIDProfile, isSubjectIDProfile bool) {
	user := utils.NewIdentity(t, mtpUserPK)
	issuer := utils.NewIdentity(t, mtpIssuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)
	var err error
	if isUserIDProfile {
		nonce = big.NewInt(10)
		userProfileID, err = core.ProfileID(user.ID, nonce)
		require.NoError(t, err)
	}

	expectedSybilID := "8903332384851738260747517773325377528299199208576629685986891704182978270332"
	expectedIssuerAuthState := "2943483356559152311923412925436024635269538717812859789851139200242297094"

	subjectID := user.ID
	nonceSubject := big.NewInt(0)
	if isSubjectIDProfile {
		nonceSubject = big.NewInt(999)
		subjectID, err = core.ProfileID(user.ID, nonceSubject)
		require.NoError(t, err)
		expectedSybilID = "15928283987833756851644249157457264609084917385190027282640632960343512336427"
	}

	// Sig claim
	claim := utils.DefaultUserClaim(t, subjectID)

	claimSig := issuer.SignClaim(t, claim)
	issuerClaimNonRevState := issuer.State(t)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)
	issuerAuthClaimMtp, issuerAuthClaimNodeAux := issuer.ClaimRevMTP(t, issuer.AuthClaim)

	secret := big.NewInt(10)
	scClaim := utils.GenerateNewStateCommitmentClaim(t, secret)
	user.AddClaim(t, scClaim)
	userClaimMtp, _ := user.ClaimMTP(t, scClaim)

	// gist
	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	require.Nil(t, err)
	err = gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
	require.Nil(t, err)

	err = gisTree.Add(context.Background(), user.IDHash(t), user.State(t))
	require.Nil(t, err)

	if invalidGist {
		gisTree, err = merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
		require.Nil(t, err)
		err = gisTree.Add(context.Background(), big.NewInt(3), big.NewInt(3))
		require.Nil(t, err)

		err = gisTree.Add(context.Background(), big.NewInt(4), big.NewInt(4))
		require.Nil(t, err)

		err = gisTree.Add(context.Background(), big.NewInt(5), big.NewInt(5))
		require.Nil(t, err)
	}

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	if invalidIdentity {
		sk := babyjub.NewRandPrivKey()
		skB := sk.Scalar().BigInt().Bytes()
		user = utils.NewIdentity(t, fmt.Sprintf("%x", skB))
	}

	inputs := InputsSig{
		IssuerClaim:                   claim,
		IssuerClaimNonRevClaimsRoot:   issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevRoot:      issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsRoot:    issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:        issuerClaimNonRevState.String(),
		IssuerClaimNonRevMtp:          issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:     issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:     issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:     issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:       claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:       claimSig.R8.Y.String(),
		IssuerClaimSignatureS:         claimSig.S.String(),
		IssuerAuthClaim:               issuer.AuthClaim,
		IssuerAuthClaimMtp:            issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:      issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi: issuerAuthClaimNodeAux.Key,
		IssuerAuthClaimNonRevMtpAuxHv: issuerAuthClaimNodeAux.Value,
		IssuerAuthClaimNonRevMtpNoAux: issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsRoot:          issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevRoot:             issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsRoot:           issuer.Rot.Root().BigInt().String(),

		IssuerClaimSchema: "180410020913331409885634153623124536270",

		StateCommitmentClaim:           scClaim,
		StateCommitmentClaimMtp:        userClaimMtp,
		StateCommitmentClaimClaimsRoot: user.Clt.Root(),
		StateCommitmentClaimRevRoot:    user.Ret.Root(),
		StateCommitmentClaimRootsRoot:  user.Rot.Root(),
		StateCommitmentClaimIdenState:  user.State(t).String(),

		GistRoot:     gistRoot,
		GistMtp:      gistProof,
		GistMtpAuxHi: gistNodAux.Key,
		GistMtpAuxHv: gistNodAux.Value,
		GistMtpNoAux: gistNodAux.NoAux,

		CRS: big.NewInt(123456789).String(),

		UserGenesisID: user.ID.BigInt().String(),
		ProfileNonce:  nonce.String(),

		ClaimSubjectProfileNonce: nonceSubject.String(),

		IssuerID:  "123",
		RequestID: "321",
		Timestamp: timestamp,
	}

	out := OutputsSig{
		UserID:          userProfileID.BigInt().String(),
		SybilID:         expectedSybilID,
		IssuerAuthState: expectedIssuerAuthState,
	}

	jsonTestData, err := json.Marshal(TestDataSig{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonTestData))
}
