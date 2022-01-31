pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "operators/notin.circuit";

/*
  Operators:
 "0" - not in
 ....
*/
template Query (nElements) {
	// signals
	signal input in;
	signal input value[nElements];
	signal input operator;
	signal output out;

	component notin = NOTIN(nElements);
	notin.in <== in;
	for(var i = 0; i<nElements; i++){notin.value[i] <== value[i];}
}