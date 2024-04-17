pragma circom 2.1.1;

include "../../../circuits/lib/utils/claimUtils.circom";
include "../../../circuits/lib/utils/tags-managing.circom";

template wrappedVerifyExpirationTime() {
    signal input expirationFlag; // claimFlags[3] (expiration flag) is set
    signal input claim[8];
    signal input timestamp;

    component check = verifyExpirationTime();
    check.expirationFlag <== AddBinaryTag()(expirationFlag);
    check.claim <== claim;
    check.timestamp <== timestamp;
}

component main = wrappedVerifyExpirationTime();
