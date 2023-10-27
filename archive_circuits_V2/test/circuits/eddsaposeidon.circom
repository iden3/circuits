pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template EdDSAPoseidonTest() {
    signal input enabled;
    signal input Ax;
    signal input Ay;

    signal input S;
    signal input R8x;
    signal input R8y;

    signal input M;

	EdDSAPoseidonVerifier()(
        enabled,
	    Ax,
        Ay,
        S,
        R8x,
        R8y,
        M
	);
}

component main = EdDSAPoseidonTest();



