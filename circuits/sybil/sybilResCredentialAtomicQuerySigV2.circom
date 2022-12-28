pragma circom 2.0.0;

include "sybilResCredentialAtomicQuerySigOffChain.circom";

component main{public [
                        requestID,
                        issuerID,
                        timestamp,
                        issuerClaimNonRevState,
                        crs,
                        gistRoot]} = SybilResCredentialAtomicQuerySigOffChain(32, 32, 32);