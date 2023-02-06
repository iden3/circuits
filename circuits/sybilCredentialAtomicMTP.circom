pragma circom 2.0.0;

include "sybil/sybilCredentialAtomicMTPOffChain.circom";

component main{public [
                        requestID,
                        issuerID,
                        timestamp,
                        claimSchema,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        crs,
                        gistRoot]} = SybilCredentialAtomicMTP(40, 40, 64);
