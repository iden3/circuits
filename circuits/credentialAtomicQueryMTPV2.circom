pragma circom 2.0.0;

include "lib/query/credentialAtomicQueryMTPV2.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        claimSchema,
                        slotIndex,
                        operator,
                        timestamp]} = CredentialAtomicQueryMTPV2(32, 32, 64);
