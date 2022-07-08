const chai = require("chai");
const path = require("path");
const F1Field = require("ffjavascript").F1Field;
const Scalar = require("ffjavascript").Scalar;
exports.p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const Fr = new F1Field(exports.p);

const wasm_tester = require("circom_tester").wasm;

const assert = chai.assert;

describe("Comparators test", function ()  {

    this.timeout(100000);

    it("Should create a comparison lessthan", async() => {
        console.log(__dirname)
        const circuit = await wasm_tester(path.join(__dirname, "./circuits/", "lessthan.circom"));

        let w;
        w = await circuit.calculateWitness({ "in": ["10", "14651237294507013008273219182214280847718990358813499091232105186081237893131"] }, true);
        const expOut = {out: 1}

        await circuit.assertOut(w, expOut);
        await circuit.checkConstraints(w);
    });
});
