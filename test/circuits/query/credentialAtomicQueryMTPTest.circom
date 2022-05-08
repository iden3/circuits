pragma circom 2.0.0;

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
