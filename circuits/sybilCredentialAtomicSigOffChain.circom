pragma circom 2.1.1;

include "sybil/sybilCredentialAtomicSigOffChain.circom";

component main{public [
                        requestID,
                        issuerID,
                        timestamp,
                        claimSchema,
                        issuerClaimNonRevState,
                        crs,
                        gistRoot]} = SybilCredentialAtomicSig(32, 32, 32);
