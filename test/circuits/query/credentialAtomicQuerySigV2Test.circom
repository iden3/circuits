pragma circom 2.0.0;

include "../../../circuits/lib/query/credentialAtomicQuerySigV2.circom";

component main{public [userStateInOnChainSmtRoot,
                        challenge,
                        issuerID,
                        issuerClaimNonRevState,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = credentialAtomicQuerySigV2(32, 32, 32, 64);
