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

    it("test query with KYCCountry credential", async () => {
        const inputs = {
            "BBJAx": "19363139996228661875544893123671950908651281664880785130944076574052990126674",
            "BBJAy": "21422557063646016455987111590224511086961434426635409038878435614418545877413",
            "BBJClaimClaimsTreeRoot": "6906696252998047340434782676950703436193238009777668188280776542867169089009",
            "BBJClaimMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "BBJClaimRevTreeRoot": "0",
            "BBJClaimRootsTreeRoot": "0",
            "challenge": "12345",
            "challengeSignatureR8x": "7026709909603894650006530956878636953570370091274737343905773785596148204072",
            "challengeSignatureR8y": "12623729239905281911019654065460505363775751538038411160486668972214601972067",
            "challengeSignatureS": "2259543530361565669528281569481763433947677281068436866714331005919980685852",
            "claim": ["3541084760699114883882170454247606663396", "358753682585156032607991143404182618036143329412223697640731109391605432320", "980", "1", "227737578865723621818874605733", "0", "0", "0"],
            "claimIssuanceClaimsTreeRoot": "13731603230335914521442894376919753815007446524287359973379359589880317722784",
            "claimIssuanceIdenState": "15836933293307196079102626646704289284946136304980757970414278866777483277967",
            "claimIssuanceMtp": ["14229847371519562490394300082490539719533095227665433899280655808527677894054", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "claimIssuanceRevTreeRoot": "0",
            "claimIssuanceRootsTreeRoot": "0",
            "claimNonRevIssuerClaimsTreeRoot": "13731603230335914521442894376919753815007446524287359973379359589880317722784",
            "claimNonRevIssuerRevTreeRoot": "0",
            "claimNonRevIssuerRootsTreeRoot": "0",
            "claimNonRevIssuerState": "15836933293307196079102626646704289284946136304980757970414278866777483277967",
            "claimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "claimNonRevMtpAuxHi": "0",
            "claimNonRevMtpAuxHv": "0",
            "claimNonRevMtpNoAux": "1",
            "claimSchema": "138261091489730249248424379929924548836",
            "id": "358753682585156032607991143404182618036143329412223697640731109391605432320",
            "operator": 0,
            "slotIndex": 2,
            "timestamp": "1640251952",
            "value": "980"
        }

        const expOut = {
            challenge: "12345",
            id: "358753682585156032607991143404182618036143329412223697640731109391605432320",
            claimSchema: "138261091489730249248424379929924548836",
            slotIndex: "2",
            operator: "0",
            value: "980",
            timestamp: "1640251952",
        }
        const w = await circuit.calculateWitness(inputs, true);

        await circuit.assertOut(w, expOut);
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

            claimIssuanceMtp: ["0",
                "0",
                "11840549358489662158957688603983199538336899326280558850217730268709009797810",
                "0"],
            claimIssuanceClaimsTreeRoot: "8493003494726860300633431973273122808125771868287442027245563585092434039664",
            claimIssuanceRevTreeRoot: "0",
            claimIssuanceRootsTreeRoot: "0",
            claimIssuanceIdenState: "7250774806265342444670050834809653548010854890881205160371587352728471237096",

            claimNonRevMtp: ["0", "0", "0", "0"],
            claimNonRevMtpNoAux: "1",
            claimNonRevMtpAuxHi: "0",
            claimNonRevMtpAuxHv: "0",
            claimNonRevIssuerClaimsTreeRoot: "8493003494726860300633431973273122808125771868287442027245563585092434039664",
            claimNonRevIssuerRevTreeRoot: "0",
            claimNonRevIssuerRootsTreeRoot: "0",
            claimNonRevIssuerState: "7250774806265342444670050834809653548010854890881205160371587352728471237096",

            slotIndex: "3",
            value: "1",
            operator: "0",
            timestamp: "1638533435"
        }

        const expOut = {
            challenge: "18446744073709551615",
            id: "318143161927515226538633402626308472116169082888716969971233931702195126272",
            claimSchema: "49",
            slotIndex: "3",
            operator: "0",
            value: "1",
            timestamp: "1638533435",
        }
        const w = await circuit.calculateWitness(inputs, true);

        await circuit.assertOut(w, expOut);
    });


})
;
