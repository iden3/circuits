pragma circom 2.0.0;

include "sybilResCredentialAtomicQueryMTPOffChain.circom";

component main{public [
                        requestID,
                        issuerID,
                        timestamp,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        crs,
                        gistRoot]} = SybilResCredentialAtomicQueryMTPOffChain(32, 32, 32);
