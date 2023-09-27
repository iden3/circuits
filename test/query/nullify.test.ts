import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test Nullify operator:", async function() {
    const tests = [
        {desc: "nullify with all inputs non zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                credProfileNonce: "999",
                fieldValue: "10",
                crs: "94313",
            },
            expOut: {nullifier: "18187891344039155928577018852912893319105381777411238186581401895728237860586"}},

        {desc: "nullify with csr = zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                credProfileNonce: "999",
                fieldValue: "10",
                crs: "0",
            },
            expOut: {nullifier: "7216061433410647105695231363702935977791263320190618761310869807370377565684"}},
        {desc: "nullify with credProfileNonce = zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                credProfileNonce: "0",
                fieldValue: "10",
                crs: "94313",
            },
            expOut: {nullifier: "0"}},
    ];

    let circuit;

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/query/", "nullifyTest.circom"));
    });

    tests.forEach(({desc, input, expOut}) => {
        it(`${desc}`, async function() {
            const w = await circuit.calculateWitness(input, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });
});
