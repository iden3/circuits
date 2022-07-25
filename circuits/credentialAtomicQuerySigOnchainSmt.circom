pragma circom 2.0.0;

include "lib/query/credentialAtomicQuerySig.circom";

component main{public [challenge,
                        verifierCorrelationID,
                        nullifierHash,
                        issuerID,
                        issuerClaimNonRevState,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = CredentialAtomicQuerySig(32, 32, 32, 64);
