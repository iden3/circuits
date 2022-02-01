pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/comparators.circom";

// nElements - number of value elements
// Example nElements = 3, '1' v ['12', '1231', '9999'], 1 not in array of values
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

    	// Greater then
    	component gt = GreaterThan(252);
    	gt.in[0] <== count;
    	gt.in[1] <== 0;

    	out <== gt.out; // 1 - if in signal in the list, 0 - if it is not
}


template NOTIN (nElements){
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

    	// Equal then
    	component eqRes = IsEqual();
    	eqRes.in[0] <== count;
    	eqRes.in[1] <== 0;

        out <== eqRes.out; // 1 - if in signal not in the list, 0 - if it is in the list

}

// nElements - number of value elements
// Example nElements = 3, '1' v ['1', '1231', '9999'], 1 in array of values
template IN_ForceEqual (nElements){
	// signals
	signal input in;
	signal input value[nElements];

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

// nElements - number of value elements
// Example nElements = 3, '1' v ['12', '1231', '9999'], 1 not in array of values
template NOTIN_ForceEqual (nElements){
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