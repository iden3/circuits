# circuits [![Tests](https://github.com/iden3/circuits/workflows/Tests/badge.svg)](https://github.com/iden3/circuits/actions?query=workflow%3ATests)

Circuits used by the iden3 core protocol.

**Warning:** This repository is in a very early stage.

The circuits of this repository are compatible with the [go-iden3-core implementation](https://github.com/iden3/go-iden3-core)

Circuits:
- [Identity Ownership](circuits/idOwnership.circom): circuit used to verify that the prover is the owner of the Identity
- [Identity Ownership Genesis](circuits/idOwnershipGenesis.circom): wrapper on top of idOwnership.circom to check the ownership only for a Genesis Id state
- [Identity State Update](circuits/idState.circom): circuit used to verify validity when updating an Identity State
- [BuildClaimKeyBBJJ](circuits/buildClaimKeyBBJJ.circom): circuit used build ClaimKeyBabyJubJub
- [BuildClaimBasicAboutId](circuits/buildClaimBasicAboutId.circom): circuit used build ClaimBasic about a specific Id 
- [Credential](circuits/credential.circom): circuit used to verify a Credential. This means that the prover is the owner of the identity, which identity is inside a ClaimBasic, and that claim is inside the MerkleTree of the Issuer identity
