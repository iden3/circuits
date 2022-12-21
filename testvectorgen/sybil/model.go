package sybil

import (
	"github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
)

const (
	userPK    = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	issuerPK  = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
	timestamp = "1642074362"
)

type Inputs struct {

	// claim of uniqueness
	IssuerClaim           *core.Claim      `json:"issuerClaim"`
	IssuerClaimMtp        []string         `json:"issuerClaimMtp"`
	IssuerClaimClaimsRoot *merkletree.Hash `json:"issuerClaimClaimsRoot"`
	IssuerClaimRevRoot    *merkletree.Hash `json:"issuerClaimRevRoot"`
	IssuerClaimRootsRoot  *merkletree.Hash `json:"issuerClaimRootsRoot"`
	IssuerClaimIdenState  string           `json:"issuerClaimIdenState"`

	IssuerClaimNonRevMtp      []string `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpNoAux string   `json:"issuerClaimNonRevMtpNoAux"`
	IssuerClaimNonRevMtpAuxHi string   `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv string   `json:"issuerClaimNonRevMtpAuxHv"`

	IssuerClaimNonRevClaimsRoot *merkletree.Hash `json:"issuerClaimNonRevClaimsRoot"`
	IssuerClaimNonRevRevRoot    *merkletree.Hash `json:"issuerClaimNonRevRevRoot"`
	IssuerClaimNonRevRootsRoot  *merkletree.Hash `json:"issuerClaimNonRevRootsRoot"`
	IssuerClaimNonRevState      string           `json:"issuerClaimNonRevState"`

	// claim of state-secret (Holder's claim)

	holderClaim           *core.Claim      `json:"holderClaim"`
	holderClaimMtp        []string         `json:"holderClaimMtp"`
	holderClaimClaimsRoot *merkletree.Hash `json:"holderClaimClaimsRoot"`
	holderClaimRevRoot    *merkletree.Hash `json:"holderClaimRevRoot"`
	holderClaimRootsRoot  *merkletree.Hash `json:"holderClaimRootsRoot"`
	holderClaimIdenState  string           `json:"holderClaimIdenState"`

	GistRoot     *merkletree.Hash   `json:"gistRoot"`
	GistMtp      []string `json:"gistMtp"`
	GistMtpAuxHi string   `json:"gistMtpAuxHi"`
	GistMtpAuxHv string   `json:"gistMtpAuxHv"`
	GistMtpNoAux string   `json:"gistMtpNoAux"`

	CRS string `json:"crs"`

	// user data
	UserGenesisID string `json:"userGenesisID"` //
	ProfileNonce  string `json:"profileNonce"`  //
	//ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"` //

}

type Outputs struct {
	UserID  string `json:"userID"`
	SybilID string `json:"sybilID"`
}

type TestDataMTPV2 struct {
	Desc string  `json:"desc"`
	In   Inputs  `json:"inputs"`
	Out  Outputs `json:"expOut"`
}
