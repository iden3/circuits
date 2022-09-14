pragma circom 2.0.0;

include "../../../circuits/lib/query/credentialAtomicQueryMTPV2.circom";

component main{public [challenge,
                       userID,
                       userState,
                       claimSchema,
                       issuerID,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = CredentialAtomicQueryMTPV2(32, 32, 64);
