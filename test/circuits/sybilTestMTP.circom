pragma circom 2.0.0;

include "../../circuits/sybil/sybilResCredentialAtomicQueryMTPOffChain.circom";

component main{public [
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        crs,
                        gistRoot]} = SybilResCredentialAtomicQueryMTPOffChain(32, 32, 32);