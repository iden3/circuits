package utils

import (
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
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
	UserID                 string `json:"userID"`
	IssuerID               string `json:"issuerID"`
	IssuerAuthState        string `json:"issuerAuthState"`
	IssuerClaimNonRevState string `json:"issuerClaimNonRevState"`
	ClaimSchema            string `json:"claimSchema"`
	SlotIndex              string `json:"slotIndex"`
	Operator               int    `json:"operator"`
	ValueHash              string `json:"valueHash"`
	Timestamp              string `json:"timestamp"`
	Merklized              string `json:"merklized"`
	ClaimPathNotExists     string `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	GistRoot               string `json:"gistRoot"`
	Challenge              string `json:"challenge"`
}

type TestDataSigV2 struct {
	Desc string                              `json:"desc"`
	In   CredentialAtomicSigOnChainV2Inputs  `json:"inputs"`
	Out  CredentialAtomicSigOnChainV2Outputs `json:"expOut"`
}
