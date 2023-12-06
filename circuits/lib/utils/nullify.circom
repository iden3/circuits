pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";

template Nullify() {
    signal input genesisID;
    signal input claimSubjectProfileNonce;
    signal input claimSchema;
    signal input verifierID;
    signal input nullifierSessionID;

    signal output nullifier;

    signal isZeroNonce <== IsZero()(claimSubjectProfileNonce);
    signal isZeroVerifierID <== IsZero()(verifierID);
    signal isZeronullifierSessionID <== IsZero()(nullifierSessionID);

    signal hash <== Poseidon(5)([genesisID, claimSubjectProfileNonce, claimSchema, verifierID, nullifierSessionID]);

    signal isZero1 <== OR()(isZeroNonce, isZeroVerifierID);
    signal isZero2 <== OR()(isZero1, isZeronullifierSessionID);

    nullifier <== Mux1()(
        [hash, 0],
        isZero2
    );
}
