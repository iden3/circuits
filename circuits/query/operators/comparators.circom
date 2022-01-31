pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/comparators.circom";

//
template NOTIN (nElements){
	// signals
	signal input in;
	signal input value[nElements];

	component eq[nElements];
	for (var i=0; i<nElements; i++) {
		eq[i] = IsEqual();
		eq[i].in[0] <== in;
		eq[i].in[1] <== value[i];
		eq[i].out === 0;
	}
}

//
template IN (nElements){
	// signals
	signal input in;
	signal input value[nElements];
	signal output out;

	component eq[nElements];
	var count = 0;
	for (var i=0; i<nElements; i++) {
		eq[i] = IsEqual();
		eq[i].in[0] <== in;
		eq[i].in[1] <== value[i];
		count += eq[i].out;
	}

	//Greater then 0
	component gt = GreaterThan(252);
	gt.in[0] <== count;
	gt.in[1] <== 0;

	gt.out === 1;
}