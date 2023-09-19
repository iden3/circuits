pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";

template Nullify() {
    signal input genesisID;
    signal input credProfileNonce;
    signal input fieldValue;
    signal input crs;

    signal output nullifier;

    signal isZeroNonce <== IsZero()(credProfileNonce);

    signal hash <== Poseidon(4)([genesisID, credProfileNonce, fieldValue, crs]);

    nullifier <== Mux1()(
        [hash, 0],
        isZeroNonce
    );
}
