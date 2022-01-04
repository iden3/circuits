pragma circom 2.0.0;

include "../credentialAtomicQuery.circom";

component main{public [challenge,
                        id,
                        hoIdenState,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = AtomicQuery(4, 40);