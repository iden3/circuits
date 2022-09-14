// Begin Poseidon Hash


function calcHash(valueArraySize, arr, poseidonParamCount = 16) {
    console.log("valueArraySize: ", valueArraySize, arr.length);
    poseidonParamCount = valueArraySize > 16 ? 16 : valueArraySize;
    console.log("poseidonParamCount", poseidonParamCount);
    let partialHashLength = valueArraySize > 16 ? (valueArraySize - (valueArraySize % poseidonParamCount)) / poseidonParamCount : 1;
    console.log("partialHashLength", partialHashLength);
    partialHashLength = valueArraySize > 16 && (valueArraySize % poseidonParamCount) != 0 ? partialHashLength + 1 : partialHashLength;
    let valueHash = [];
    const getHash = (arr) => {
        return arr.reduce((a, b) => a + b, 0);
    };
    const partialHash = [];
    const lastIndex = partialHashLength - 1;
    for (var i = 0; i < partialHashLength; i++) {
        let paramsCount = poseidonParamCount;
        if (lastIndex == i) {
            if (valueArraySize % poseidonParamCount != 0) {
                paramsCount = valueArraySize % poseidonParamCount;
                console.log("last index call", lastIndex);
            }
        }
        console.log("iteration", i, "paramsCount", paramsCount)
        partialHash[i] = [];
        for (var j = 0; j < paramsCount; j++) {
            partialHash[i].push(arr[i * poseidonParamCount + j]);
            console.log("value Index", i * poseidonParamCount + j);
        }
        valueHash.push(getHash(partialHash[i]));
    }
    return getHash(valueHash);
}

const arrSize = 6
const arr = new Array(arrSize).fill('').map((i, idx) => idx);
console.log(calcHash(arrSize, arr, 16));
