# circuits [![Tests](https://github.com/iden3/circuits/workflows/Tests/badge.svg)](https://github.com/iden3/circuits/actions?query=workflow%3ATests) 

Circuits used by the iden3 core protocol.

The circuits of this repository are compatible with the [go-iden3-core implementation](https://github.com/iden3/go-iden3-core)

# Building and trusted setup

First install the npm dependencies:

```bash
npm ci
```

Then build the circuit and do the "trusted" setup:

```bash
./compile-circuit.sh CIRCUIT_PATH PTAU_FILE_PATH
```

Examples:

```bash
./compile-circuit.sh circuits/auth.circom build/powersOfTau28_hez_final_16.ptau
./compile-circuit.sh circuits/stateTransition.circom build/powersOfTau28_hez_final_16.ptau
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

## Push docker container to github packages
1. Create [PAT](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token);
2. Login to github registry:
    ```bash
    echo <PAT> | docker login ghcr.io -u <GITHUB_NAME> --password-stdin
    ```
3. Build docker image with tag:
    ```bash
    docker build -t ghcr.io/iden3/circom:<version> .
    ```
4. Push docker image:
    ```bash
    docker push ghcr.io/iden3/circom:<version>
    ```
5. Update `.github/workflows/main.yaml` to the new image:
    ```yaml
    ...
        container:
          image: ghcr.io/iden3/circom:<version>
    ...
    ```

## Security Audits
1. [Trail of Bits](https://github.com/trailofbits/publications/tree/master/reviews) has performed a security audit of our circuits and compiled a report on May 3, 2024: [2024-05-polygonlabs-iden3circuits-securityreview.pdf](https://raw.githubusercontent.com/iden3/audits/adc81d1bce9a7bde9577eb4389998d60cfac9619/circuits/2024-05-polygonlabs-iden3circuits-securityreview.pdf)