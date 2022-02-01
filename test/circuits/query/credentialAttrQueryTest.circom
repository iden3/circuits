pragma circom 2.0.0;

include "../../../circuits/query/credentialAttrQuery.circom";

component main{public [challenge,
                       id,
                       hoIdenState,
                       claimSchema,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = AtomicQueryIN(4, 4, 4);
