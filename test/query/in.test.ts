import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test IN operator:", async function() {
    const tests = [
        {desc: "value in the list",
            input: {
                in: "123",
                value: ["123", "9999", "5555"],
            },
            expOut: {out: "1"}},

        {desc: "multiple values in the list",
            input: {
                in: "123",
                value: ["123", "123", "999"],
            },
            expOut: {out: "1"}},
        {desc: "value not in the list",
            input: {
                in: "123",
                value: ["124", "888", "999"],
            },
            expOut: {out: "0"}},

    ];

    let circuit;

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/query/", "inTest.circom"));
    });

    tests.forEach(({desc, input, expOut}) => {
        it(`${desc}`, async function() {
            const w = await circuit.calculateWitness(input, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });
});
