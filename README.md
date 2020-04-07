# circuits [![Build Status](https://travis-ci.org/iden3/circuits.svg?branch=master)](https://travis-ci.org/iden3/circuits)

Circuits used by the iden3 core protocol.

**Warning:** This repository is in a very early stage.

The circuits of this repository are compatible with the [go-iden3-core implementation](https://github.com/iden3/go-iden3-core)

Circuits:
- [Identity Ownership](circuits/idOwnership.circom): circuit used to verify that the prover is the owner of the Identity
- [Identity State Update](circuits/idState.circom): circuit used to verify validity when updating an Identity State
- [BuildClaimAuthKSignBBJJ](circuits/buildClaimAuthKSignBBJJ.circom): circuit used build ClaimAuthKSignBabyJub 
