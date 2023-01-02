pragma circom 2.0.0;

include "sybilResCredentialAtomicQuerySigOffChain.circom";

component main{public [
                        requestID,
                        issuerID,
                        timestamp,
                        issuerClaimSchema,
                        issuerClaimNonRevState,
                        crs,
                        gistRoot]} = SybilResCredentialAtomicQuerySigOffChain(32, 32, 32);