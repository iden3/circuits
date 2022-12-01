const path = require("path");
const F1Field = require("ffjavascript").F1Field;
const Scalar = require("ffjavascript").Scalar;
exports.p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const Fr = new F1Field(exports.p);

const wasm_tester = require("circom_tester").wasm;
const c_tester = require("circom_tester").c;

const test_vectors = {
    "10 < 0": {
        "in": ["10", "0"],
        "expected": 0
    },
    "10 < 10": {
        "in": ["10", "10"],
        "expected": 0
    },
    "10 < 11": {
        "in": ["10", "11"],
        "expected": 1
    },
    "10 < -1": { // log in wasm witness calculator shows -1 == 4294967295n, and so 10 < 4294967295 == true
        "in": ["10", "-1"],
        "expected": 0
    },
    "10 < -max(uint32)": { // log in wasm shows -max(uint32) == 1n, and so 10 < 1 == false
        "in": ["10", "-4294967295"],
        "expected": 0
    },
    "10 < -(max(uint32)-10)": { // log in wasm shows -(max(uint32)-10) == 11n
        "in": ["10", "-4294967285"],
        "expected": 0
    },
    "10 < -(max(uint32)-20)": { // log in wasm shows -(max(uint32)-20) == 21n
        "in": ["10", "-4294967275"],
        "expected": 0
    },
    "10 < -(max(uint32)+1)": { // (max(uint32)+1) will not fit into uint32, so it becomes uint64, and log in wasm shows here 18446744069414584320n
        "in": ["10", "-4294967296"],
        "expected": 0
    },
    // in the docs negative numbers are introduced for Relational operators:
    // val(z) = z-p  if p/2 +1 <= z < p
    // val(z) = z,    otherwise.
    // https://docs.circom.io/circom-language/basic-operators/#relational-operators
    "10 < p/2 (max positive number)": {
        "in": ["10", "10944121435919637611123202872628637544274182200208017171849102093287904247808"],
        "expected": 1
    },
    "10 < p/2+1 (max negative number)": {
        "in": ["10", "10944121435919637611123202872628637544274182200208017171849102093287904247809"],
        "expected": 0
    },
    "10 < p-1 (eq to -1)": {
        "in": ["10", "21888242871839275222246405745257275088548364400416034343698204186575808495616"],
        "expected": 0
    },
    "10 < x, x > (p-1)/2, x < p-1": {
        "in": ["10", "14651237294507013008273219182214280847718990358813499091232105186081237893131"],
        "expected": 0
    },

};


describe.skip("WASM: Less than", function ()  {
    let circuit;
    this.timeout(100000);

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "./circuits/", "lessthan.circom"));
    });

    for (const test_name in test_vectors) {
        it(test_name, async() => {
            let w = await circuit.calculateWitness({ "in": test_vectors[test_name].in }, true);
            const expOut = {out: test_vectors[test_name].expected}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    }
});

describe.skip("C: Less than", function ()  {
    let circuit;
    this.timeout(100000);

    before(async function() {
        circuit = await c_tester(path.join(__dirname, "./circuits/", "lessthan.circom"))
    });

    for (const test_name in test_vectors) {
        it(test_name, async() => {
            let w = await circuit.calculateWitness({ "in": test_vectors[test_name].in }, true);
            const expOut = {out: test_vectors[test_name].expected}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    }
});
