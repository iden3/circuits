pragma circom 2.0.0;

include "lib/query/credentialAtomicQuerySigV2.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimNonRevState,
                        claimSchema,
                        slotIndex,
                        operator,
                        timestamp]} = CredentialAtomicQuerySigV2(32, 32, 64);
