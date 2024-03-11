pragma circom 2.1.1;

include "../../../circuits/lib/utils/claimUtils.circom";

template getClaimSubjectOtherIdenWrapper() {
    signal input claim[8];
    signal output id;

    // get header flags from claim.
    component header = getClaimHeader();
    header.claim <== claim;

    id <== getClaimSubjectOtherIden()(claim, header.claimFlags);
}

component main{public[claim]} = getClaimSubjectOtherIdenWrapper();
