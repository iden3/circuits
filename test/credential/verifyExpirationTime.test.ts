import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test verifyExpirationTime",  function() {
    let circuit;
    let testData = {in:{},expOut:{}};

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/credential", "credential_verifyExpirationTime.circom"));
    });

    afterEach( async ()=>{
        const w = await circuit.calculateWitness(testData.in, true);
        await circuit.assertOut(w, testData.expOut);
    })

    it("#success", async () => {
        const claim = ["2722258935367507707706996859454145691697",
            "0",
            "0",
            "0",
            "30803922974473213664682835967", // expiration 1669884010
            "0",
            "0",
            "0"];

        testData.in = {claim: claim, timestamp: 1669884010};
        testData.expOut = {};
    });

});
