import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("Attr query test", function () {

    this.timeout(100000);

    let circuit;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "../circuits", "attributeQuery.circom"));
    });

    after(async function () {
        circuit.release()
    })

    it("Should check all mandatory verifications", async () => {
        const inputs = {
            id: "318143161927515226538633402626308472116169082888716969971233931702195126272",
            BBJAx: "17640206035128972995519606214765283372613874593503528180869261482403155458945",
            BBJAy: "20634138280259599560273310290025659992320584624461316485434108770067472477956",
            BBJClaimMtp: [
                "0",
                "0",
                "0",
                "0"
            ],
            BBJClaimClaimsTreeRoot: "11840549358489662158957688603983199538336899326280558850217730268709009797810",
            BBJClaimRevTreeRoot: "0",
            BBJClaimRootsTreeRoot: "0",

            challenge: "18446744073709551615",
            challengeSignatureR8x: "15362679770907874738275889574050493764730246578025270990145279227034033898138",
            challengeSignatureR8y: "1734057881969138137988951540873571701565511589327619105700976155858739179141",
            challengeSignatureS: "2590256937949796750100851683506177766726455914396114252813300799841566245330",

            claim: ["680564733841876926926749214863536422912",
                "318143161927515226538633402626308472116169082888716969971233931702195126272",
                "1",
                "0",
                "0",
                "0",
                "0",
                "0"],

            claimIssuanceMtp:["11840549358489662158957688603983199538336899326280558850217730268709009797810",
            "0","0","0"],
            claimIssuanceClaimsTreeRoot:"18766293311419241686915793834088680261962037794772087760406555415962820950959",
            claimIssuanceRevTreeRoot:"0",
            claimIssuanceRootsTreeRoot:"0",
            claimIssuanceIdenState:"9115907658539645961679754808388327634044088045274630440729337443535633552945",

        }

        const expOut = {challenge: "18446744073709551615", id: "318143161927515226538633402626308472116169082888716969971233931702195126272"}
        const w = await circuit.calculateWitness(inputs, true);

        await circuit.assertOut(w, expOut);
    });


});
