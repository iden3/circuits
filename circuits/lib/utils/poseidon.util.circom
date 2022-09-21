pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

template PoseidonUtil(valueArraySize) {
	signal input in[valueArraySize];
	signal output out;
    //Because of the way the Poseidon hash function is implemented for Solidity, the max number of inputs must be 6
    var batchSize = 6;
    var moduloRest = valueArraySize % batchSize;
    var difftoRound = batchSize - moduloRest;
    var fullLength = valueArraySize + difftoRound;
    var totalIterations = fullLength / batchSize;
    var fullHash = 1;

    component poseidon6[totalIterations];
    component poseidon2[totalIterations];

    for(var i = 0; i < totalIterations; i++) {
        var iterationIndex = i * batchSize;  
        poseidon6[i] = Poseidon(batchSize);
        poseidon6[i].inputs[0] <== in[
            iterationIndex >= valueArraySize ? 0 : iterationIndex
        ];
       
        poseidon6[i].inputs[1] <== in[
            iterationIndex + 1 >= valueArraySize ? 0 : iterationIndex + 1
        ];
        poseidon6[i].inputs[2] <== in[
            iterationIndex + 2 >= valueArraySize ? 0 : iterationIndex + 2
        ];
        poseidon6[i].inputs[3] <== in[
            iterationIndex + 3 >= valueArraySize ? 0 : iterationIndex + 3
        ];
        poseidon6[i].inputs[4] <== in[
            iterationIndex + 4 >= valueArraySize ? 0 : iterationIndex + 4
        ];
        poseidon6[i].inputs[5] <== in[
            iterationIndex + 5 >= valueArraySize ? 0 : iterationIndex + 5
        ];
        poseidon2[i] = Poseidon(2);
        poseidon2[i].inputs[0] <== fullHash;
        poseidon2[i].inputs[1] <== poseidon6[i].out;
        fullHash = poseidon2[i].out;
    }
    
    out <== fullHash;
}
