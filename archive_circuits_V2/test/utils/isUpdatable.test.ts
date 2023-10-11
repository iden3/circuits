import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test", function () {
    let circuit;
    let testData = {in:{},expOut:{}}

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/utils", "utils_isUpdatable.circom"));
    })

    afterEach( async ()=>{
        const w = await circuit.calculateWitness(testData.in, true);
        await circuit.assertOut(w, testData.expOut);
    })

    it("#not updatable", async () => {
        const claim = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        testData.in = {claimFlags: claim};
        testData.expOut = {out: 0};
    });

    it("#updatable", async () => {
        const claim = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        testData.in = {claimFlags: claim};
        testData.expOut = {out: 1};
    });
})
