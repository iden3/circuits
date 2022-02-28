pragma circom 2.0.0;

include "../query/credentialAtomicQueryMTPWithRelay.circom";

component main{public [challenge,
                        userID,
                        relayState,
                        issuerID,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = CredentialAtomicQueryMTPWithRelay(40, 40, 40, 16);
