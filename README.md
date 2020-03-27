# circuits [![Build Status](https://travis-ci.org/iden3/circuits.svg?branch=master)](https://travis-ci.org/iden3/circuits)

Circuits used by the iden3 core protocol.

[WIP]

**Warning:** This repository is in a very early stage.

- [Identity State Update](circuits/idState.circom): circuit used to verify validity when updating an Identity State
  - [BuildClaimAuthKSignBBJJ](circuits/buildClaimAuthKSignBBJJ.circom): circuit used build ClaimAuthKSignBabyJub compatible with the [go-iden3-core version](https://github.com/iden3/go-iden3-core/blob/master/core/claims/claimAuthorizeKSignBabyJub.go)
