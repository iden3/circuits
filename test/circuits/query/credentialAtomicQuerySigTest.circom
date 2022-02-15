pragma circom 2.0.0;

include "../../../circuits/query/credentialAtomicQuerySig.circom";

component main{public [challenge,
                       id,
                       hoIdenState,
                       claimSchema,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = CredentialAtomicQuerySig(40, 40, 4);
