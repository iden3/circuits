pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";


// getClaimSubjectOtherIden checks that a claim Subject is OtherIden and outputs the identity within.
template poseidonUtil(valueArraySize) {
	signal input in[valueArraySize];
	signal output out;

   // Begin Poseidon Hash: max input size is 16
    // Cout of perameters per partial poseidon hash function
    var poseidonParamCount = valueArraySize > 16 ? 16 : valueArraySize;
    // Length of partial poseidon hash functions array
    var partialHashLength = valueArraySize > 16 ? (valueArraySize - (valueArraySize % poseidonParamCount)) / poseidonParamCount : 1;
    // in case values has valueArraySize % 16 != 0 we need to add one more iteration
    partialHashLength = valueArraySize > 16 && (valueArraySize % poseidonParamCount) != 0 ? partialHashLength + 1 : partialHashLength;

    component fullHash = Poseidon(partialHashLength); 
    component partialHash[partialHashLength]; 

    var lastIndex = partialHashLength - 1;
    for(var i = 0; i < partialHashLength; i++) {
         var paramsCount = poseidonParamCount;
        if(lastIndex == i){
            if(valueArraySize % poseidonParamCount != 0){
                paramsCount = valueArraySize % poseidonParamCount;
            }
        }
        partialHash[i] = Poseidon(paramsCount);  
        for(var j = 0; j < paramsCount; j++) {
            partialHash[i].inputs[j] <== in[i*poseidonParamCount + j];
        }     
        fullHash.inputs[i] <== partialHash[i].out;   
    }
    
    out <== fullHash.out;
}
