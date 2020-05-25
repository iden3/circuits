# circuits [![Tests](https://github.com/iden3/circuits/workflows/Tests/badge.svg)](https://github.com/iden3/circuits/actions?query=workflow%3ATests) [![npm](https://img.shields.io/npm/v/@iden3/circuits)](https://img.shields.io/npm/v/@iden3/circuits)

Circuits used by the iden3 core protocol.

**Warning:** This repository is in a very early stage.

The circuits of this repository are compatible with the [go-iden3-core implementation](https://github.com/iden3/go-iden3-core)

Circuits:
- [Identity Ownership](circuits/idOwnership.circom): circuit used to verify that the prover is the owner of the Identity
- [Identity Ownership Genesis](circuits/idOwnershipGenesis.circom): wrapper on top of idOwnership.circom to check the ownership only for a Genesis Id state
- [Identity State Update](circuits/idState.circom): circuit used to verify validity when updating an Identity State
- [BuildClaimKeyBBJJ](circuits/buildClaimKeyBBJJ.circom): circuit used build ClaimKeyBabyJubJub
- [BuildClaimBasicAboutId](circuits/buildClaimBasicAboutId.circom): circuit used build ClaimBasic about a specific Id 
- [Credential](circuits/credential.circom): circuit used to verify a
  Credential. This means that the prover is the owner of the identity, and the
  identity is inside a claim with Subject OtherIden, and that claim is inside
  the MerkleTree of the Issuer identity, and the claim is not revoked.

Examples of circuits usage:
- [Identity State Update](circuits/examples/idState.circom): Identity state
  update circuit with genesis proofs of at most 4 levels.
- [Credential Demo Wrapper](circuits/examples/credentialDemoWrapper.circom):
  Credential demo circuit that proves ownership of a claim of type
  ClaimOtherIden (with some values set to 0 for simplicity).

# Building and trusted setup

First install the npm dependencies:
```
npm ci
```

Then build the circuit and do the "trusted" setup:
```
./compile-circuit.sh CIRCUIT_PATH
```

Examples:
```
./compile-circuit.sh circuits/examples/idState.circom
./compile-circuit.sh circuits/examples/credentialDemoWrapper.circom
```
