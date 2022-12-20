pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

// Because of the way the Poseidon hash function is implemented for Solidity, the max number of inputs must be 6
template ValuesHasher(valueArraySize) {
	signal input in[valueArraySize];
	signal output out;
    // batch size is 5 because 1 input is reserved for the hash of the previous iteration
    var batchSize = 5;
    var totalIterations = 1;
    if (valueArraySize >  batchSize) {
        var moduloRest = valueArraySize % batchSize;
        var difftoRound = batchSize - moduloRest;
        var fullLength = valueArraySize + difftoRound;
        totalIterations = fullLength / batchSize;
    }
    var fullHash = 0;

    component poseidon[totalIterations];
    for(var i = 0; i < totalIterations; i++) {
        var iterationIndex = i * batchSize;
        poseidon[i] = Poseidon(6);
        
        poseidon[i].inputs[0] <== fullHash;
        poseidon[i].inputs[1] <== in[
            iterationIndex >= valueArraySize ? 0 : iterationIndex
        ];
        poseidon[i].inputs[2] <== in[
            iterationIndex + 1 >= valueArraySize ? 0 : iterationIndex + 1
        ];
        poseidon[i].inputs[3] <== in[
            iterationIndex + 2 >= valueArraySize ? 0 : iterationIndex + 2
        ];
        poseidon[i].inputs[4] <== in[
            iterationIndex + 3 >= valueArraySize ? 0 : iterationIndex + 3
        ];
        poseidon[i].inputs[5] <== in[
            iterationIndex + 4 >= valueArraySize ? 0 : iterationIndex + 4
        ];

        fullHash = poseidon[i].out;
        
    }
    
    out <== fullHash;
}
