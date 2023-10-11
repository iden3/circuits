pragma circom 2.0.0;

include "sybil/sybilCredentialAtomicSigOffChain.circom";

component main{public [
                        requestID,
                        issuerID,
                        timestamp,
                        claimSchema,
                        issuerClaimNonRevState,
                        crs,
                        gistRoot]} = SybilCredentialAtomicSig(40, 40, 64);
