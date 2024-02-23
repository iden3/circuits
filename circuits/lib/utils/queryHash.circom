pragma circom 2.1.1;
include "./spongeHash.circom";

template QueryHash(maxValueArraySize) {
    signal input value[maxValueArraySize];
    signal input claimSchema;
    signal input slotIndex;
    signal input operator;
    signal input claimPathKey;
    signal input claimPathNotExists;
    signal input valueArraySize;
    signal input merklized;
    signal input verifierID;
    signal input isRevocationChecked;
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
        claimPathNotExists,
        valueHash
    ]);

     out <== Poseidon(6)([
        firstPartQueryHash,
        valueArraySize,
        merklized,
        verifierID,
        isRevocationChecked,
        nullifierSessionID
    ]);
}