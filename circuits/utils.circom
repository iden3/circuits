// bigEntian turns the value v into a bit array of len bits in big endian
function bigEndian(v, len) {
	var res[len];
	for (var i=0; i<len/8; i++) {
		for (var j=0; j<8; j++) {
			res[len - (i+1)*8 + j] = (v >> (i*8 + j)) & 1;
		}
	}
	return res;
}

