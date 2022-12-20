package sybil

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"math/big"
	"test/utils"
	"testing"
)

func generateTestData(t *testing.T, desc, fileName string) {
	var err error

	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)
	//if isUserIDProfile {
	//	nonce = big.NewInt(10)
	//	userProfileID, err = core.ProfileID(user.ID, nonce)
	//	require.NoError(t, err)
	//}

	subjectID := user.ID
	//nonceSubject := big.NewInt(0)
	//if isSubjectIDProfile {
	//	nonceSubject = big.NewInt(999)
	//	subjectID, err = core.ProfileID(user.ID, nonceSubject)
	//	require.NoError(t, err)
	//}

	claim := utils.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)
	require.NoError(t, err)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	inputs := Inputs{
		UserGenesisID: user.ID.BigInt().String(),
		ProfileNonce:  nonce.String(),
		//ClaimSubjectProfileNonce:        nonceSubject.String(),
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
	}

	out := Outputs{
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

	jsonTestData, err := json.Marshal(TestDataMTPV2{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonTestData))

}
