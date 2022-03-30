pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/*
  Operators:
 "0" - equals
 "1" - less-than
 "2" - greater-than
*/
template Query () {
   // signals
	signal input in;
	signal input value;
	signal input operator;
	signal output out;

  // operation components
	component eq = IsEqual();
	eq.in[0] <== in;
  eq.in[1] <== value;

	// Ask Jordi about size 252. Why not 253? or 254
	component lt = LessThan(252);
	lt.in[0] <== in;
  lt.in[1] <== value;

//  component gt = GreaterThan(252);
//  gt.in[0] <== field;
//  gt.in[1] <== value;

  // mux
	component mux = Mux1();
	component n2b = Num2Bits(2);
	n2b.in <== operator;

	n2b.out[0] ==> mux.s;
	eq.out ==> mux.c[0];
	lt.out ==> mux.c[1];
//	gt.out ==> mux.c[2];

  // output
	mux.out ==> out;
}