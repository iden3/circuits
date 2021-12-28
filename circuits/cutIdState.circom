pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/bitify.circom";

template cutId() {
	signal input in;
	signal output out;

	component idBits = Num2Bits(256);
	idBits.in <== in;

	component cutted = Bits2Num(256-16-16-8);
	for (var i=16; i<256-16-8; i++) {
		cutted.in[i-16] <== idBits.out[i];
	}
	out <== cutted.out;
}

template cutState() {
	signal input in;
	signal output out;

	component stateBits = Num2Bits(256);
	stateBits.in <== in;

	component cutted = Bits2Num(256-16-16-8);
	for (var i=0; i<256-16-16-8; i++) {
		cutted.in[i] <== stateBits.out[i+16+16+8];
	}
	out <== cutted.out;
}
