pragma circom 2.0.0;

include "sybilResCredentialAtomicQuerySigOffChain.circom";

component main{public [
                        // uniqueness claim
                        issuerClaimNonRevState,
                        issuerClaimSchema,
                        claimPathKey,
                        claimPathNotExists,

                        // state secret claim
                        holderClaimIdenState,
                        holderClaimSchema,
                        crs,
                        gist
]} = SybilResCredentialAtomicQuerySigOffChain(32, 32, 32);