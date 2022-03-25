pragma circom 2.0.0;

include "../../../circuits/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                       id,
                       hoIdenState,
                       claimSchema,
                       issuerID,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = CredentialAtomicQueryMTP(40, 40, 16);
