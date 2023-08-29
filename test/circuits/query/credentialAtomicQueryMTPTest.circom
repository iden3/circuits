pragma circom 2.1.1;

include "../../../circuits/lib/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                       userID,
                       userState,
                       claimSchema,
                       issuerID,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = CredentialAtomicQueryMTP(32, 32, 64);
