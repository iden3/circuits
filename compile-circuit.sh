#!/bin/sh

set -e

compile_and_ts() {
    CIRCUIT_PATH="$1"
    CIRCUIT=`basename "$CIRCUIT" .circom`
    CONTRACT=`python -c "print(\"${CIRCUIT}\".capitalize())"`

    mkdir -p "$CIRCUIT"
    cd "$CIRCUIT"

    echo "Built at `date`" > info.txt
    git show --summary >> info.txt
    cp "$CIRCUIT_PATH" circuit.circom

    set -x
    time circom "$CIRCUIT_PATH" --r1cs circuit.r1cs --wasm circuit.wasm --sym circuit.sym
    snarkjs r1cs info circuit.r1cs
    snarkjs r1cs export json circuit.r1cs circuit.r1cs.json

#    time snarkjs setup -r circuit.r1cs --pk proving_key.json --vk verification_key.json
    time snarkjs groth16 setup circuit.r1cs ../powersOfTau28_hez_final_15.ptau circuit_0000.zkey

    ENTROPY1=$(head -c 1024 /dev/urandom | LC_CTYPE=C tr -dc 'a-zA-Z0-9' | head -c 128)
    ENTROPY2=$(head -c 1024 /dev/urandom | LC_CTYPE=C tr -dc 'a-zA-Z0-9' | head -c 128)
    ENTROPY3=$(head -c 1024 /dev/urandom | LC_CTYPE=C tr -dc 'a-zA-Z0-9' | head -c 128)

    time snarkjs zkey contribute circuit_0000.zkey circuit_0001.zkey --name="1st Contribution" -v -e="$ENTROPY1"
    time snarkjs zkey contribute circuit_0001.zkey circuit_0002.zkey --name="2nd Contribution" -v -e="$ENTROPY2"
    time snarkjs zkey contribute circuit_0002.zkey circuit_0003.zkey --name="3rd Contribution" -v -e="$ENTROPY3"
    time snarkjs zkey verify circuit.r1cs ../powersOfTau28_hez_final_15.ptau circuit_0003.zkey
    time snarkjs zkey beacon circuit_0003.zkey circuit_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"
    time snarkjs zkey verify circuit.r1cs ../powersOfTau28_hez_final_15.ptau circuit_final.zkey
    time snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
    time snarkjs zkey export json circuit_final.zkey circuit_final.zkey.json

    #time node "${WASMSNARK_TOOLS}/buildpkey.js" -i proving_key.json -o proving_key.bin
    #time "${GO_PROVER_PATH}/cli" -convert -pk proving_key.json -pkbin proving_key.go.bin
    time snarkjs zkey export solidityverifier circuit_final.zkey verifier.sol
    set +x

    #sed -i 's/null/["0","0","0"]/g' proving_key.json

    #sed -i "s/solidity ^0.5.0/solidity ^0.6.0/g" verifier.sol
    #sed -i "s/gas/gas()/g" verifier.sol
    #sed -i "s/return the sum/return r the sum/g" verifier.sol
    #sed -i "s/return the product/return r the product/g" verifier.sol
    #sed -i "s/contract Verifier/contract ${CONTRACT}Verifier/g" verifier.sol
    #sed -i "s/Pairing/${CONTRACT}Pairing/g" verifier.sol
}

if [ "$#" -ne 1 ]
then
    echo "Usage: $0 CIRCUIT_PATH" >&2
    exit 1
fi

set -u

CIRCUIT="$(pwd)/$1"
PATH="$(pwd)/node_modules/.bin:$PATH"
WASMSNARK_TOOLS="$(pwd)/node_modules/wasmsnark/tools"
GO_PROVER_PATH="$(pwd)/../go-circom-prover-verifier/cli/"

OLD_PWD="$(pwd)"
cd "$GO_PROVER_PATH"
go build
cd "$OLD_PWD"

# npm ci
mkdir -p build

cd build
compile_and_ts "$CIRCUIT"
