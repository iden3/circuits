package sybil

import (
	"github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
)

const (
	mtpUserPK   = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	mtpIssuerPK = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"

	sigUserPK   = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
	sigIssuerPK = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d"
)

type InputsMTP struct {

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

	// HolderClaim           *core.Claim      `json:"holderClaim"`
	// HolderClaimMtp        []string         `json:"holderClaimMtp"`
	// HolderClaimClaimsRoot *merkletree.Hash `json:"holderClaimClaimsRoot"`
	// HolderClaimRevRoot    *merkletree.Hash `json:"holderClaimRevRoot"`
	// HolderClaimRootsRoot  *merkletree.Hash `json:"holderClaimRootsRoot"`
	HolderClaimIdenState string `json:"holderClaimIdenState"`

	GistRoot     *merkletree.Hash `json:"gistRoot"`
	GistMtp      []string         `json:"gistMtp"`
	GistMtpAuxHi string           `json:"gistMtpAuxHi"`
	GistMtpAuxHv string           `json:"gistMtpAuxHv"`
	GistMtpNoAux string           `json:"gistMtpNoAux"`

	CRS string `json:"crs"`

	// user data
	UserGenesisID string `json:"userGenesisID"`
	ProfileNonce  string `json:"profileNonce"`
}

type InputsSig struct {

	// claim of uniqueness
	IssuerAuthClaim      *core.Claim `json:"issuerAuthClaim"`
	IssuerAuthClaimMtp   []string    `json:"issuerAuthClaimMtp"`
	IssuerAuthClaimsRoot string      `json:"issuerAuthClaimsRoot"`
	IssuerAuthRevRoot    string      `json:"issuerAuthRevRoot"`
	IssuerAuthRootsRoot  string      `json:"issuerAuthRootsRoot"`

	IssuerAuthClaimNonRevMtp      []string `json:"issuerAuthClaimNonRevMtp"`
	IssuerAuthClaimNonRevMtpAuxHi string   `json:"issuerAuthClaimNonRevMtpAuxHi"`
	IssuerAuthClaimNonRevMtpAuxHv string   `json:"issuerAuthClaimNonRevMtpAuxHv"`
	IssuerAuthClaimNonRevMtpNoAux string   `json:"issuerAuthClaimNonRevMtpNoAux"`

	IssuerClaim                 *core.Claim `json:"issuerClaim"`
	IssuerClaimNonRevClaimsRoot string      `json:"issuerClaimNonRevClaimsRoot"`
	IssuerClaimNonRevRevRoot    string      `json:"issuerClaimNonRevRevRoot"`
	IssuerClaimNonRevRootsRoot  string      `json:"issuerClaimNonRevRootsRoot"`

	IssuerClaimNonRevState    string   `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp      []string `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi string   `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv string   `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux string   `json:"issuerClaimNonRevMtpNoAux"`

	IssuerClaimSignatureR8X string `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y string `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS   string `json:"issuerClaimSignatureS"`

	// claim of state-secret (Holder's claim)

	// HolderClaim           *core.Claim      `json:"holderClaim"`
	// HolderClaimMtp        []string         `json:"holderClaimMtp"`
	// HolderClaimClaimsRoot *merkletree.Hash `json:"holderClaimClaimsRoot"`
	// HolderClaimRevRoot    *merkletree.Hash `json:"holderClaimRevRoot"`
	// HolderClaimRootsRoot  *merkletree.Hash `json:"holderClaimRootsRoot"`
	HolderClaimIdenState string `json:"holderClaimIdenState"`

	GistRoot     *merkletree.Hash `json:"gistRoot"`
	GistMtp      []string         `json:"gistMtp"`
	GistMtpAuxHi string           `json:"gistMtpAuxHi"`
	GistMtpAuxHv string           `json:"gistMtpAuxHv"`
	GistMtpNoAux string           `json:"gistMtpNoAux"`

	CRS string `json:"crs"`

	// user data
	UserGenesisID string `json:"userGenesisID"`
	ProfileNonce  string `json:"profileNonce"`
}

type Outputs struct {
	UserID  string `json:"userID"`
	SybilID string `json:"sybilID"`
}

type TestDataMTP struct {
	Desc string    `json:"desc"`
	In   InputsMTP `json:"inputs"`
	Out  Outputs   `json:"expOut"`
}

type TestDataSig struct {
	Desc string    `json:"desc"`
	In   InputsSig `json:"inputs"`
	Out  Outputs   `json:"expOut"`
}