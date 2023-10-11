import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test", function () {
    let circuit;
    let testData = {in:{},expOut:{}}

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/utils", "utils_getClaimSubjectOtherIden.circom"));
    })

    afterEach( async ()=>{
        const w = await circuit.calculateWitness(testData.in, true);
        await circuit.assertOut(w, testData.expOut);
    })

    it("#self subject", async () => {
        // generated with: claim, err := NewClaim(schemaHash)
        const claim = ["0", "0", "0", "0", "0", "0", "0", "0"]

        testData.in = {claim: claim};
        testData.expOut = {id: "0"};
    })

    it("#subject position index", async () => {
        // generated with
        /*
            id, err := IDFromString("114vgnnCupQMX4wqUBjg5kUya3zMXfPmKc9HNH4TSE")
	        claim, err := NewClaim(schemaHash, WithID(id, IDPositionIndex))
        */
        const claim = [
            "680564733841876926926749214863536422912",
            "436519927146362718106026092069337374589932286960467750019485473174216638464",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
        ];

        testData.in = {claim: claim};
        testData.expOut = {id: "436519927146362718106026092069337374589932286960467750019485473174216638464"};
    });

    it("#subject position value", async () => {
        // generated with
        /*
            id, err := IDFromString("114vgnnCupQMX4wqUBjg5kUya3zMXfPmKc9HNH4TSE")
	        claim, err := NewClaim(schemaHash, WithID(id, IDPositionValue))
        */
        const claim = [
            "1020847100762815390390123822295304634368",
            "0",
            "0",
            "0",
            "0",
            "436519927146362718106026092069337374589932286960467750019485473174216638464",
            "0",
            "0",
        ];

        testData.in = {claim: claim};
        testData.expOut = {id: "436519927146362718106026092069337374589932286960467750019485473174216638464"};
    });
})
