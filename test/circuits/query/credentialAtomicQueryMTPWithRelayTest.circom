pragma circom 2.0.0;

include "../../../circuits/query/credentialAtomicQueryMTPWithRelay.circom";

component main{public [challenge,
                       userID,
                       relayState,
                       claimSchema,
                       issuerID,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = CredentialAtomicQueryMTPWithRelay(40, 40, 40, 16);
