pragma circom 2.0.0;

include "lib/query/credentialJsonLDAtomicQueryMTP.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        claimSchema,
                        claimPathKey,
                        operator,
                        value,
                        timestamp]} = CredentialJsonLDAtomicQueryMTP(32, 32, 32, 64);
