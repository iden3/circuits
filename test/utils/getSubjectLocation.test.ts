import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test", function () {
    let circuit;
    let testData = {in:{},expOut:{}}

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/utils", "utils_getSubjectLocation.circom"));
    })

    afterEach( async ()=>{
        const w = await circuit.calculateWitness(testData.in, true);
        await circuit.assertOut(w, testData.expOut);
    })

    it("#self location", async () => {
        // this claim generated with claim, err := NewClaim(schemaHash)
        const claim = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        testData.in = {claimFlags: claim};
        testData.expOut = {subject: 0};
    });

    it("#index location", async () => {
        // this claim generated with claim, err := NewClaim(schemaHash, WithID(ID{}, IDPositionIndex))
        const claim = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        testData.in = {claimFlags: claim};
        testData.expOut = {subject: 2};
    });

    it("#value location", async () => {
        // this claim generated with `claim, err := NewClaim(schemaHash, WithID(ID{}, IDPositionValue))`
        const claim = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        testData.in = {claimFlags: claim};
        testData.expOut = {subject: 3};
    });
})
