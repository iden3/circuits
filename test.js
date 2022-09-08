// Begin Poseidon Hash


function calcHash(valueArraySize, arr, maxPoseidonMaxParamSize = 16) {
    const poseidonValueArraySize = (valueArraySize - (valueArraySize % maxPoseidonMaxParamSize)) / maxPoseidonMaxParamSize;
    let valueHash = [];
    const getHash = (arr) => {
        return arr.reduce((a, b) => a + b, 0);
    };
    const partialHash = [];
    const lastIndex = poseidonValueArraySize - 1;
    for (var i = 0; i < poseidonValueArraySize; i++) {
        var size = 0;
        if (i == lastIndex) {
            size = valueArraySize % maxPoseidonMaxParamSize;
        } else {
            size = maxPoseidonMaxParamSize;
        }
        console.log("i", i, "size", size);
        partialHash[i] = [];
        for (var j = 0; j < size; j++) {
            partialHash[i].push(arr[i * size + j]);
        }
        valueHash.push(getHash(partialHash[i]));
    }
    console.log(partialHash);
    console.log(valueHash);
    return getHash(valueHash);

}

const arrSize = 65
const arr = new Array(arrSize).fill('').map((i, idx) => idx);
console.log(calcHash(arrSize, arr, 12));
