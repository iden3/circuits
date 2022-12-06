const path = require("path");

const wasm_tester = require("circom_tester").wasm;
const c_tester = require("circom_tester").c;

// In circom docs negative numbers are introduced for Relational operators:
// val(z) = z-p  if p/2 +1 <= z < p
// val(z) = z,    otherwise.
// p == 21888242871839275222246405745257275088548364400416034343698204186575808495617
// See: https://docs.circom.io/circom-language/basic-operators/#relational-operators
// Wasm witness calculator calculates negative numbers incorrectly
const test_vectors = {
    "0 == p": {
        "in": ["0", "21888242871839275222246405745257275088548364400416034343698204186575808495617"],
    },
    "1 == p+1 overflow": {
        "in": ["1", "21888242871839275222246405745257275088548364400416034343698204186575808495618"],
    },
    "-1 == p-1": { // log in wasm witness calculator shows -1 == 4294967295
        "in": ["-1", "21888242871839275222246405745257275088548364400416034343698204186575808495616"],
    },
    "-max(uint32) == p-max(uint32)": { // abs value of number fits into uint32
        "in": ["-4294967295", "21888242871839275222246405745257275088548364400416034343698204186571513528322"],
    },
    "-(max(uint32)-10) == p-(max(uint32)-10)": { // abs value of number fits into uint32
        "in": ["-4294967285", "21888242871839275222246405745257275088548364400416034343698204186571513528332"],
    },
    "-(max(uint32)+1) == p-(max(uint32)+1)": { // (max(uint32)+1) will not fit into uint32, so it becomes uint64
        "in": ["-4294967296", "21888242871839275222246405745257275088548364400416034343698204186571513528321"],
    },
    "-(max(uint64)) == p-(max(uint64))": { // max(uint64) fits into uint64
        "in": ["-18446744073709551615", "21888242871839275222246405745257275088548364400416034343679757442502098944002"],
    },
    "-(max(uint64)+1) == p-(max(uint64)+1)": { // (max(uint64)+1) will not fit into uint64, so it becomes uint96
        "in": ["-18446744073709551616", "21888242871839275222246405745257275088548364400416034343679757442502098944001"],
    },
    "-(max(uint96)+1) == p-(max(uint96)+1)": { // (max(uint64)+1) will not fit into uint64, so it becomes uint96
        "in": ["-79228162514264337593543950337", "21888242871839275222246405745257275088548364400336806181183939848982264545280"],
    },
    "-p/2 (max negative number)": {
        "in": ["-10944121435919637611123202872628637544274182200208017171849102093287904247808", "10944121435919637611123202872628637544274182200208017171849102093287904247809"],
    },
};


describe("WASM: Eq", function ()  {
    let circuit;
    this.timeout(100000);

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "./circuits/", "eq.circom"));
    });

    for (const test_name in test_vectors) {
        it(test_name, async() => {
            let w = await circuit.calculateWitness({ "in": test_vectors[test_name].in }, true);
            const expOut = {out: 1}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    }
});

describe.skip("C: Eq", function ()  {
    let circuit;
    this.timeout(100000);

    before(async function() {
        circuit = await c_tester(path.join(__dirname, "./circuits/", "eq.circom"))
    });

    for (const test_name in test_vectors) {
        it(test_name, async() => {
            let w = await circuit.calculateWitness({ "in": test_vectors[test_name].in }, true);
            const expOut = {out: 1}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    }
});
