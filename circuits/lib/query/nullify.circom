pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/mux2.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";

template Nullify() {
    signal input genesisID;
    signal input claimSubjectProfileNonce;
    signal input claimSchema;
    signal input fieldValue;
    signal input verifierID;
    signal input crs;

    signal output nullifier;

    signal isZeroNonce <== IsZero()(claimSubjectProfileNonce);
    signal isZeroVerifierID <== IsZero()(verifierID);

    signal hash <== Poseidon(6)([genesisID, claimSubjectProfileNonce, claimSchema, fieldValue, verifierID, crs]);

    nullifier <== Mux2()(
        [hash, 0, 0, 0],
        [isZeroNonce, isZeroVerifierID]
    );
}
