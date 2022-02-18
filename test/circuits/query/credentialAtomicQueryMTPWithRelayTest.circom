pragma circom 2.0.0;

include "../../../circuits/query/credentialAtomicQueryMTPWithRelay.circom";

component main{public [challenge,
                       id,
                       reIdenState,
                       claimSchema,
                       issuerID,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = CredentialAtomicQueryMTPWithRelay(4, 4, 4, 4);