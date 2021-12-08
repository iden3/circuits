pragma circom 2.0.0;

include "../credentialAtomicQuery.circom";

component main{public [challenge,
                        id,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = AtomicQuery(20, 20);