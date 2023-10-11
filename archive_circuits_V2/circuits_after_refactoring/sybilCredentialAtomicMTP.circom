pragma circom 2.1.1;

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
