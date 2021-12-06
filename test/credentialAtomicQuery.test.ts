import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("test claim query", function () {

    this.timeout(100000);

    let circuit;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/examples", "credentialAtomicQuery.circom"));
    });

    after(async function () {
        circuit.release()
    })

    it("Should check all claim and identity mandatory verifications", async () => {
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

            claimSchema: "49",
            claim: ["3402823669209384634633746074317682114609",
                "318143161927515226538633402626308472116169082888716969971233931702195126272",
                "10",
                "0",
                "30803922965249841627828060161",
                "0",
                "0",
                "0"],

            claimIssuanceMtp:["0",
                "0",
                "11840549358489662158957688603983199538336899326280558850217730268709009797810",
                "0"],
            claimIssuanceClaimsTreeRoot:"8493003494726860300633431973273122808125771868287442027245563585092434039664",
            claimIssuanceRevTreeRoot:"0",
            claimIssuanceRootsTreeRoot:"0",
            claimIssuanceIdenState:"7250774806265342444670050834809653548010854890881205160371587352728471237096",

            claimNonRevMtp:["0","0","0","0"],
            claimNonRevMtpNoAux:"1",
            claimNonRevMtpAuxHi:"0",
            claimNonRevMtpAuxHv:"0",
            claimNonRevIssuerClaimsTreeRoot:"8493003494726860300633431973273122808125771868287442027245563585092434039664",
            claimNonRevIssuerRevTreeRoot:"0",
            claimNonRevIssuerRootsTreeRoot:"0",
            claimNonRevIssuerState:"7250774806265342444670050834809653548010854890881205160371587352728471237096",

            fieldIndex:"3",
            value:"1",
            operator:"0",
            timestamp:"1638533435"
        }

        const expOut = {challenge: "18446744073709551615",
                        id: "318143161927515226538633402626308472116169082888716969971233931702195126272",
                        claimSchema:"49",
                        fieldIndex:"3",
                        operator:"0",
                        value:"1",
                        timestamp:"1638533435"}
        const w = await circuit.calculateWitness(inputs, true);

        await circuit.assertOut(w, expOut);
    });


});
