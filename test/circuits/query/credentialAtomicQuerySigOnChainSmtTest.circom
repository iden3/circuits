pragma circom 2.0.0;

include "../../../circuits/lib/query/credentialAtomicQuerySigOnChainSmt.circom";

component main{public [userStateInOnChainSmtRoot,
                        userCorrelationID,
                        userNullifier,
                        challenge,
                        issuerID,
                        issuerClaimNonRevState,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = CredentialAtomicQuerySigOnChainSmt(32, 32, 32, 64);
