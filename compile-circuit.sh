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
    snarkjs info -r circuit.r1cs
    time snarkjs setup -r circuit.r1cs --pk proving_key.json --vk verification_key.json
    time snarkjs generateverifier --vk verification_key.json -v verifier.sol
    set +x

    sed -i 's/null/["0","0","0"]/g' proving_key.json

    sed -i "s/solidity ^0.5.0/solidity ^0.6.0/g" verifier.sol
    sed -i "s/gas/gas()/g" verifier.sol
    sed -i "s/return the sum/return r the sum/g" verifier.sol
    sed -i "s/return the product/return r the product/g" verifier.sol
    sed -i "s/contract Verifier/contract ${CONTRACT}Verifier/g" verifier.sol
    sed -i "s/Pairing/${CONTRACT}Pairing/g" verifier.sol
}

if [ "$#" -ne 1 ]
then
    echo "Usage: $0 CIRCUIT_PATH" >&2
    exit 1
fi

set -u

CIRCUIT=`readlink -f "$1"`
PATH=`pwd`/node_modules/.bin:$PATH

# npm ci
mkdir -p build

cd build
compile_and_ts "$CIRCUIT"
