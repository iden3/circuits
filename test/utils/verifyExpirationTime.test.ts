import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test verifyExpirationTime",  function() {
    let circuit;
    let testData = {in:{},expOut:{}};

    before(async function() {
        this.timeout(5000);
        circuit = await wasm_tester(path.join(__dirname, "../circuits/utils", "utils_verifyExpirationTime.circom"));
    });

    afterEach( async ()=>{
        const w = await circuit.calculateWitness(testData.in, true);
        await circuit.assertOut(w, testData.expOut);
    })

    it("#success claim with expiration time", async () => {
        const claim = ["8166776806102523123120990578362437074969", // claim type = 25, expiration flag 1
            "0",
            "0",
            "0",
            "30803922974473213664682835967", // expiration 1669884010
            "0",
            "0",
            "0"];

        testData.in = {enabled: "1", claim: claim, timestamp: 1669884009};
        testData.expOut = {};
    });

    it("#success expiration flag 0", async () => {
        const claim = ["5444517870735015415413993718908291383321", // claim type = 25, expiration flag 0, expiration 0
            "0",
            "0",
            "0",
            "18446744073709551615", // expiration 0
            "0",
            "0",
            "0"];

        testData.in = {enabled: "1", claim: claim, timestamp: 1669884009};
        testData.expOut = {};
    });

    it("#success expiration flag 1, timestamp equal to expiration", async () => {
        const claim = ["2722258935367507707706996859454145691673", // claim type = 25, expiration flag 1
            "0",
            "0",
            "0",
            "30802373438747650025492316159", // expiration 1669800009
            "0",
            "0",
            "0"];

        testData.in = {enabled: "1", claim: claim, timestamp: 1669800008};
        testData.expOut = {};
    });

});
