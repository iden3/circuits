pragma circom 2.0.0;

include "lib/query/credentialAtomicQuerySigOnChainSmt.circom";

component main{public [challenge,
                        correlationID,
                        nullifier,
                        issuerID,
                        issuerClaimNonRevState,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = CredentialAtomicQuerySigOnChainSmt(32, 32, 32, 64);
