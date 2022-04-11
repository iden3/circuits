pragma circom 2.0.0;

include "lib/query/credentialAtomicQuerySig.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerState,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = CredentialAtomicQuerySig(40, 40, 16);
