pragma circom 2.0.0;

include "../../circuits/sybil/sybilResCredentialAtomicQuerySigOffChain.circom";

component main{public [
                        issuerClaimNonRevState,
                        crs,
                        gistRoot]} = SybilResCredentialAtomicQuerySigOffChain(32, 32, 32);