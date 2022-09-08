pragma circom 2.0.0;

include "lib/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        claimSchema,
                        slotIndex,
                        operator,
                        timestamp]} = CredentialAtomicQueryMTP(32, 32, 64);
