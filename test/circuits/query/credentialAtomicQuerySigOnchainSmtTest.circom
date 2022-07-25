pragma circom 2.0.0;

include "../../../circuits/lib/query/credentialAtomicQuerySigOnchainSmt.circom";

component main{public [challenge,
                        verifierCorrelationID,
                        nullifierHash,
                        issuerID,
                        issuerClaimNonRevState,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = CredentialAtomicQuerySigOnchainSmt(32, 32, 32, 64);
