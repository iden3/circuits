pragma circom 2.1.1;

include "../../../circuits/lib/utils/claimUtils.circom";
include "../../../circuits/lib/utils/tags-managing.circom";

template wrappedVerifyClaimSignature(){
    signal input enabled;
    signal input claimHash;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input pubKeyX;
    signal input pubKeyY;

    component check = verifyClaimSignature();
    check.enabled <== AddBinaryTag()(enabled);
    check.claimHash <== claimHash;
    check.sigR8x <== sigR8x;
    check.sigR8y <== sigR8y;
    check.sigS <== sigS;
    check.pubKeyX <== pubKeyX;
    check.pubKeyY <== pubKeyY;
}

component main = wrappedVerifyClaimSignature();
