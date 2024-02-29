pragma circom 2.1.1;
include "./spongeHash.circom";

template QueryHash(maxValueArraySize) {
    signal input value[maxValueArraySize];
    signal input claimSchema;
    signal input slotIndex;
    signal input operator;
    signal input claimPathKey;
    signal input valueArraySize;
    signal input merklized;
    signal input isRevocationChecked;
    signal input verifierID;
    signal input nullifierSessionID;

    signal output out;

    /////////////////////////////////////////////////////////////////
    // Calculate query hash
    /////////////////////////////////////////////////////////////////
    // 4950 constraints (SpongeHash+Poseidon)
    signal valueHash <== SpongeHash(maxValueArraySize, 6)(value); // 6 - max size of poseidon hash available on-chain
    signal firstPartQueryHash <== Poseidon(6)([
        claimSchema,
        slotIndex,
        operator,
        claimPathKey,
        merklized,
        valueHash
    ]);

     out <== Poseidon(6)([
        firstPartQueryHash,
        valueArraySize,
        isRevocationChecked,
        verifierID,
        nullifierSessionID,
        0
    ]);
}
