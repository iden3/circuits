package sigv2

import (
	json2 "encoding/json"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/stretchr/testify/require"
	"test/utils"
)

const (
	userPK   = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	issuerPK = "8156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
)

func Test_CredentialAtomicQuerySigV2_JSON(t *testing.T) {

	id, err := utils.NewIdentity(userPK)
	require.NoError(t, err)

	state, err := id.State()
	require.NoError(t, err)

	mtp, err := id.AuthMTPStrign()

	r := struct {
		IssuerID                 *big.Int    `json:"issuerID"`
		IssuerAuthClaim          *core.Claim `json:"issuerAuthClaim"`
		IssuerAuthClaimMtp       []string    `json:"issuerAuthClaimMtp"`
		IssuerAuthClaimsTreeRoot *big.Int    `json:"issuerAuthClaimsTreeRoot"`
		IssuerAuthRevTreeRoot    *big.Int    `json:"issuerAuthRevTreeRoot"`
		IssuerAuthRootsTreeRoot  *big.Int    `json:"issuerAuthRootsTreeRoot"`
		IssuerAuthState          *big.Int    `json:"issuerAuthState"`
	}{
		IssuerID:                 id.ID.BigInt(),
		IssuerAuthClaim:          id.AuthClaim,
		IssuerAuthClaimMtp:       mtp,
		IssuerAuthClaimsTreeRoot: id.Clt.Root().BigInt(),
		IssuerAuthRevTreeRoot:    id.Ret.Root().BigInt(),
		IssuerAuthRootsTreeRoot:  id.Rot.Root().BigInt(),
		IssuerAuthState:          state,
	}

	json, err := json2.Marshal(r)
	t.Log(string(json))

	t.Log("ID:", id.ID.String())
	t.Log("ID int:", id.ID.BigInt().String())
	did, err := core.ParseDIDFromID(id.ID)
	require.NoError(t, err)

	t.Log("DID:", did.String())
}

func TestIssueClaim(t *testing.T) {
	user, err := utils.NewIdentity(userPK)
	require.NoError(t, err)

	issuer, err := utils.NewIdentity(userPK)
	require.NoError(t, err)

	claim, err := utils.DefaultUserClaim(user.ID)
	require.NoError(t, err)

	// Sig claim
	claimSig, err := issuer.SignClaimBBJJ(claim)
	require.NoError(t, err)

	issuerClaimNonRevState, err := issuer.State()
	require.NoError(t, err)

	claimNonRevMtp, _, err := issuer.ClaimRevMTP(claim)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := utils.PrepareProof(claimNonRevMtp)

	authClMTP, _, err := issuer.ClaimRevMTP(issuer.AuthClaim)
	require.NoError(t, err)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux := utils.PrepareProof(authClMTP)

	s := struct {
		// user data
		UserGenesisID            string `json:"userGenesisID"`
		Nonce                    string `json:"nonce"`
		ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"`

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
		Operator  int      `json:"operator"`
		SlotIndex int      `json:"slotIndex"`
		Timestamp string   `json:"timestamp"`
		Value     []string `json:"value"`
	}{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           "0",
		ClaimSubjectProfileNonce:        "0",
		IssuerID:                        issuer.ID.BigInt().String(),
		IssuerClaim:                     claim,
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:          issuerClaimNonRevState.String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key.BigInt().String(),
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value.BigInt().String(),
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:         claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:         claimSig.R8.Y.String(),
		IssuerClaimSignatureS:           claimSig.S.String(),
		IssuerAuthClaim:                 issuer.AuthClaim,
		IssuerAuthClaimMtp:              issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:        issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi:   issuerAuthClaimNodeAux.Key.BigInt().String(),
		IssuerAuthClaimNonRevMtpAuxHv:   issuerAuthClaimNodeAux.Value.BigInt().String(),
		IssuerAuthClaimNonRevMtpNoAux:   issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsTreeRoot:        issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevTreeRoot:           issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsTreeRoot:         issuer.Rot.Root().BigInt().String(),
		ClaimSchema:                     "180410020913331409885634153623124536270",
		Operator:                        1,
		SlotIndex:                       2,
		Timestamp:                       "1642074362",
		Value:                           []string{"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
	}

	json, err := json2.Marshal(s)
	require.NoError(t, err)

	t.Log(string(json))

}

func TestIssueClaimToProfile(t *testing.T) {
	user, err := utils.NewIdentity(userPK)
	require.NoError(t, err)

	issuer, err := utils.NewIdentity(userPK)
	require.NoError(t, err)

	// Generate profile
	nonce := big.NewInt(10)
	profileID, err := core.ProfileID(user.ID, nonce)
	require.NoError(t, err)

	claim, err := utils.DefaultUserClaim(profileID)
	require.NoError(t, err)

	// Sig claim
	claimSig, err := issuer.SignClaimBBJJ(claim)
	require.NoError(t, err)

	issuerClaimNonRevState, err := issuer.State()
	require.NoError(t, err)

	claimNonRevMtp, _, err := issuer.ClaimRevMTP(claim)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := utils.PrepareProof(claimNonRevMtp)

	authClMTP, _, err := issuer.ClaimRevMTP(issuer.AuthClaim)
	require.NoError(t, err)

	issuerAuthClaimMtp, issuerAuthClaimNodeAux := utils.PrepareProof(authClMTP)

	s := struct {
		// user data
		UserGenesisID            string `json:"userGenesisID"`
		Nonce                    string `json:"nonce"`
		ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"`

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
		Operator  int      `json:"operator"`
		SlotIndex int      `json:"slotIndex"`
		Timestamp string   `json:"timestamp"`
		Value     []string `json:"value"`
	}{
		UserGenesisID:                   user.ID.BigInt().String(),
		Nonce:                           "",
		ClaimSubjectProfileNonce:        nonce.String(),
		IssuerID:                        issuer.ID.BigInt().String(),
		IssuerClaim:                     claim,
		IssuerClaimNonRevClaimsTreeRoot: issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:          issuerClaimNonRevState.String(),
		IssuerClaimNonRevMtp:            issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:       issuerClaimNonRevAux.Key.BigInt().String(),
		IssuerClaimNonRevMtpAuxHv:       issuerClaimNonRevAux.Value.BigInt().String(),
		IssuerClaimNonRevMtpNoAux:       issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:         claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:         claimSig.R8.Y.String(),
		IssuerClaimSignatureS:           claimSig.S.String(),
		IssuerAuthClaim:                 issuer.AuthClaim,
		IssuerAuthClaimMtp:              issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:        issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi:   issuerAuthClaimNodeAux.Key.BigInt().String(),
		IssuerAuthClaimNonRevMtpAuxHv:   issuerAuthClaimNodeAux.Value.BigInt().String(),
		IssuerAuthClaimNonRevMtpNoAux:   issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsTreeRoot:        issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevTreeRoot:           issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsTreeRoot:         issuer.Rot.Root().BigInt().String(),
		ClaimSchema:                     "180410020913331409885634153623124536270",
		Operator:                        1,
		SlotIndex:                       2,
		Timestamp:                       "1642074362",
		Value:                           []string{"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
	}

	json, err := json2.Marshal(s)
	require.NoError(t, err)

	t.Log(string(json))
	t.Log("ProfileID:", profileID.BigInt().String())

}
