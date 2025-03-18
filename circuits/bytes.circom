pragma circom 2.1.9;

function MAX_BYTES_IN_FIELD() {
    return 31;
}

function computeIntChunkLength(byteLength) {
    var packSize = MAX_BYTES_IN_FIELD();

    var remain = byteLength % packSize;
    var numChunks = (byteLength - remain) / packSize;
    if (remain > 0) {
        numChunks += 1;
    }

    return numChunks;
}

template PackBytes(maxBytes) {
    var packSize = MAX_BYTES_IN_FIELD();
    var maxInts = computeIntChunkLength(maxBytes);

    signal input in[maxBytes];
    signal output out[maxInts];

    signal intSums[maxInts][packSize];

    for (var i = 0; i < maxInts; i++) {
        for(var j=0; j < packSize; j++) {
            var idx = packSize * i + j;
            var bt = idx >= maxBytes ? 0 : in[idx];
            if (j == 0) {
                intSums[i][j] <== bt;
            } else {
                intSums[i][j] <== intSums[i][j-1] * 256 + bt;
            }
        }
    }

    // Last item of each chunk is the final sum
    for (var i = 0; i < maxInts; i++) {
        out[i] <== intSums[i][packSize-1];
    }
}

template DigitBytesToInt(n) {
    signal input in[n];

    signal output out;

    signal sums[n+1];
    sums[0] <== 0;

    for(var i = 0; i < n; i++) {
        sums[i + 1] <== 10 * sums[i] + (in[i] - 48);
    }

    out <== sums[n];
}

template BytesConverter(n) {
    signal input in[n];
    signal output out[n];
    
    component is255[n];
    for (var i = 0; i < n; i++) {
        is255[i] = IsEqual();
        is255[i].in[0] <== 255;
        is255[i].in[1] <== in[i];

        out[i] <== is255[i].out * (32 - in[i]) + in[i];
    }
}
