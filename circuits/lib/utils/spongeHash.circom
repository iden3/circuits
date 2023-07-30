pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

// Because of the way the Poseidon hash function is implemented for Solidity, the max number of inputs must be 6
template SpongeHash(arraySize, hashFnBatchSize) {
	signal input in[arraySize];
	signal output out;
    var batchSize = hashFnBatchSize - 1; // 1 input is reserved for the hash of the previous iteration
    var iterationCount = 0;
    component firstPoseidon = Poseidon(hashFnBatchSize);
    for(var i = 0; i < hashFnBatchSize; i++) {
        firstPoseidon.inputs[i] <== getArrayValueByIndex(in, arraySize, i);
    }

    var restLength = arraySize - hashFnBatchSize > 0 ? arraySize - hashFnBatchSize : 0;
	if (restLength > 0) {
		var r = restLength % batchSize;
		var diff = r == 0 ? 0 : batchSize - r;
		iterationCount = (restLength + diff) / batchSize;
	}

    signal fullHash[iterationCount+1];

    fullHash[0] <== firstPoseidon.out;

    component poseidon[iterationCount];
    for(var i = 0; i < iterationCount; i++) {
        var elemIdx = i * batchSize + hashFnBatchSize ;
        poseidon[i] = Poseidon(hashFnBatchSize);
        
        poseidon[i].inputs[0] <== fullHash[i];

        for (var j = 0; j < batchSize; j++)
        {
            poseidon[i].inputs[j+1] <== getArrayValueByIndex(in, arraySize, elemIdx + j);
        }

        fullHash[i+1] <== poseidon[i].out;
    }
    
    out <== fullHash[iterationCount];
}


function getArrayValueByIndex(valueArray, arraySize, idx) {
    if(idx < arraySize) {
        return valueArray[idx];
    } else{
        return 0;
    }
}
