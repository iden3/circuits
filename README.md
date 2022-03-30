# circuits [![Tests](https://github.com/iden3/circuits/workflows/Tests/badge.svg)](https://github.com/iden3/circuits/actions?query=workflow%3ATests) [![npm](https://img.shields.io/npm/v/@iden3/circuits)](https://img.shields.io/npm/v/@iden3/circuits)

Circuits used by the iden3 core protocol.

**Warning:** This repository is in a very early stage.

The circuits of this repository are compatible with the [go-iden3-core implementation](https://github.com/iden3/go-iden3-core)

Circuits:

- [Identity State Update](circuits/idState.circom): circuit used to verify validity when updating an Identity State
- [Credential](circuits/credential.circom): circuit used to verify a
  Credential. This means that the prover is the owner of the identity, and the
  identity is inside a claim with Subject OtherIden, and that claim is inside
  the MerkleTree of the Issuer identity, and the claim is not revoked.

Examples of circuits usage:

- [Identity State Update](circuits/idState.circom): Identity state
  update circuit with genesis proofs of at most 4 levels.

# Building and trusted setup

First install the npm dependencies:

```bash
npm ci
```

The compilation circuit converts the proving key to the
`go-circom-prover-verifier` binary format with `.go.bin` extension. For that,
the
[`go-circom-prover-verifier`](https://github.com/iden3/go-circom-prover-verifier)
respository needs to be checked out in the same folder where the `circuits`
repository is found. `go` must be installed in the system as well.

Then build the circuit and do the "trusted" setup:

```bash
./compile-circuit.sh CIRCUIT_PATH
```

Examples:

```bash
./compile-circuit.sh circuits/examples/idState.circom
./compile-circuit.sh circuits/examples/credentialDemoWrapper.circom
```

## Work with `s3_util.js` script

**Note**: Run `npm i` and ensure that environment _ACCESS_KEY_ID_ and _SECRET_ACCESS_KEY_ variables are defined. Script works with _./build_ folder which is located in project.

```bash

export ACCESS_KEY_ID=...
export SECRET_ACCESS_KEY=...

```

`s3_util.js` was written for:

- Uploading circuits which are located in`./build` folder to S3 bucket in zip file. Next example uploads to S3 bucket (default bucket is `iden3-circuits-bucket`) with name `v1.zip`.

```bash
node s3_util.js add v1
```

- Compressing circuits from `./build` folder to zip and save it to root project folder with name `v1.zip`. Example:

```bash
node s3_util.js zip v1
```

- Removing zip file from S3 bucket (default bucket `iden3-circuits-bucket`) Example:

```bash
node s3_util.js rm v1
```
