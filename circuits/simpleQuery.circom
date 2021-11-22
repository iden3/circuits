pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/*This circuit template multiplies in1 and in2.*/

template Query () {
   // Declaration of signals.
	signal input field;
	signal input value;
	signal input sign;
	signal output out;

	component eq = IsEqual();
	eq.in[0] <== field;
  eq.in[1] <== value;

	//Ask Jordi about size 252. Why not 253? or 254
	component lt = LessThan(252);
	lt.in[0] <== field;
  lt.in[1] <== value;

//  component gt = GreaterThan(252);
//  gt.in[0] <== field;
//  gt.in[1] <== value;

	component mux = Mux1();
	component n2b = Num2Bits(2);
	sign ==> n2b.in;

	n2b.out[0] ==> mux.s;
	eq.out ==> mux.c[0];
	lt.out ==> mux.c[1];
//	gt.out ==> mux.c[2];

	mux.out ==> out;

}