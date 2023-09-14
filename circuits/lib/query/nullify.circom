pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";

template Nullify() {
    signal input enabled;
    signal input genesisID;
    signal input credProfileNonce;
    signal input fieldValue;
    signal input crs;

    signal output nullifier;

    signal isZeroNonce <== IsZero()(credProfileNonce);

    // fail if credProfileNonce is zero (todo: and if crs is zero too?)
    // TODO: do we want to fail here or just return zero?
    ForceEqualIfEnabled()(enabled, [isZeroNonce, 0]);

    nullifier <== Poseidon(4)([genesisID, credProfileNonce, fieldValue, crs]);
}
