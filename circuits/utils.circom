// bigEntian turns the value v into a bit array of len bits in big endian
function bigEndian(v, len) {
	var res[256];
	for (var i=0; i<len/8; i++) {
		for (var j=0; j<8; j++) {
			res[len - (i+1)*8 + j] = (v >> (i*8 + j)) & 1;
		}
	}
	return res;
}

// bigEntian turns the value in into a bit array of len bits in big endian
template bigEndianT(len) {
    signal input in;
	signal output out[len];
	for (var i=0; i<len/8; i++) {
		for (var j=0; j<8; j++) {
		    var bit = (in >> (i*8 + j)) & 1;
		    var outI = len - (i+1)*8 + j;
			out[outI] <== bit;
			// error[T3001]: Non quadratic constraints are not allowed!
		}
	}
}
