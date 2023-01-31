pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

// Because of the way the Poseidon hash function is implemented for Solidity, the max number of inputs must be 6
template ValueHasher(valueArraySize) {
	signal input in[valueArraySize];
	signal output out;
    // batch size is 5 because 1 input is reserved for the hash of the previous iteration
    var batchSize = 5;
    var iterationCount = 0;
	var hashFnBatchSize = 6;
    component firstPoseidon = Poseidon(hashFnBatchSize);
    for(var i = 0; i < hashFnBatchSize; i++) {
        firstPoseidon.inputs[i] <== getArrayValueByIndex(in, valueArraySize, i);
    }

    var restLength = valueArraySize - hashFnBatchSize;
	if (restLength > batchSize) {
		var r = restLength % batchSize;
		var diff = r == 0 ? 0 : batchSize - r;
		iterationCount = (restLength + diff) / batchSize;
	}

    var fullHash = firstPoseidon.out;

    component poseidon[iterationCount];
    for(var i = 0; i < iterationCount; i++) {
        var elemIdx = i * batchSize + hashFnBatchSize ;
        poseidon[i] = Poseidon(hashFnBatchSize);
        
        poseidon[i].inputs[0] <== fullHash;

        poseidon[i].inputs[1] <== getArrayValueByIndex(in, valueArraySize, elemIdx);

        poseidon[i].inputs[2] <== getArrayValueByIndex(in, valueArraySize, elemIdx + 1);

        poseidon[i].inputs[3] <== getArrayValueByIndex(in, valueArraySize, elemIdx + 2);

        poseidon[i].inputs[4] <== getArrayValueByIndex(in, valueArraySize, elemIdx + 3);

        poseidon[i].inputs[5] <== getArrayValueByIndex(in, valueArraySize, elemIdx + 4);

        fullHash = poseidon[i].out;
        
    }
    
    out <== fullHash;
}


function getArrayValueByIndex(valueArray, valueArraySize, idx) {

   if(idx < valueArraySize) {
        return valueArray[idx];
    } else{
        return 0;
    }
}
