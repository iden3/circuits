pragma circom 2.0.0;

include "../../../circuits/lib/query/credentialAtomicQueryMTPWithRelay.circom";

component main{public [challenge,
                       userID,
                       relayState,
                       claimSchema,
                       issuerID,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = CredentialAtomicQueryMTPWithRelay(32, 32, 32, 64);
