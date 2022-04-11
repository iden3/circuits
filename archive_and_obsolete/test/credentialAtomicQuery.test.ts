import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("test claim query", function() {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits/examples", "credentialAtomicQuery.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                reduceConstraints: false,
            },
        );

    });

    after(async () => {
        circuit.release()
    })

    it("Should check all claim and identity mandatory verifications", async () => {
        const inputs = {
            id: "318143161927515226538633402626308472116169082888716969971233931702195126272",
            hoIdenState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",

            hoClaimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
            authClaimMtp: ["0", "0", "0", "0"],
            authClaim : [
                "251025091000101825075425831481271126140",
                "0",
                "17640206035128972995519606214765283372613874593503528180869261482403155458945",
                "20634138280259599560273310290025659992320584624461316485434108770067472477956",
                "15930428023331155902",
                "0",
                "0",
                "0",
            ],

            hoRevTreeRoot: "0",
            authClaimNonRevMtp: ["0", "0", "0", "0"],
            authClaimNonRevMtpNoAux: "1",
            authClaimNonRevMtpAuxHi: "0",
            authClaimNonRevMtpAuxHv: "0",

            hoRootsTreeRoot: "0",

            challenge: "1",
            challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",

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
            timestamp: "1638533435",
        }

        const expOut = {
            challenge: "1",
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
    it("Should check all claim and identity mandatory verifications 2 ", async () => {
        const inputs = {
            "authClaim": [
            "164867201768971999401702181843803888060",
            "0",
            "12225130456654256223376963051941203620326225083606194689476519876505501366857",
            "4143065209228126376868475523887894312173720313577533887436724620918815452826",
            "0",
            "0",
            "0",
            "0"
        ],
            "authClaimMtp": [
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0"
        ],
            "authClaimNonRevMtp": [
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0"
        ],
            "authClaimNonRevMtpAuxHi": "0",
            "authClaimNonRevMtpAuxHv": "0",
            "authClaimNonRevMtpNoAux": "1",
            "hoRevTreeRoot": "0",
            "hoRootsTreeRoot": "0",
            "challenge": "84239",
            "challengeSignatureR8x": "10297751443687340001464148676187251951363118116982140693372785835337030824197",
            "challengeSignatureR8y": "5188724465855403281326665438269244489188871034956182205768315414226961367241",
            "challengeSignatureS": "711287429550914102323810940842376834266545821670565701127228716139501237904",
            "claim": [
            "3677203805624134172815825715044445108615",
            "70764531162446535095600399295545291100108866293857525238033639063549444096",
            "19960424",
            "1",
            "227737578870302868152440495697",
            "0",
            "0",
            "0"
        ],
            "claimIssuanceClaimsTreeRoot": "20448718956753874366824400224880844425478857480677084793844095260090854167329",
            "claimIssuanceIdenState": "17726593429517467953665096867609458893631733731938810742510121508969881380671",
            "claimIssuanceMtp": [
            "4196282865145809997146838113544215557438462402114434957497569934994319405658",
            "0",
            "0",
            "0",
            "14458579046592212869787627756870170136294067174842392373570270465579226833822",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0"
        ],
            "claimIssuanceRevTreeRoot": "0",
            "claimIssuanceRootsTreeRoot": "0",
            "claimNonRevIssuerClaimsTreeRoot": "20448718956753874366824400224880844425478857480677084793844095260090854167329",
            "claimNonRevIssuerRevTreeRoot": "0",
            "claimNonRevIssuerRootsTreeRoot": "0",
            "claimNonRevIssuerState": "17726593429517467953665096867609458893631733731938810742510121508969881380671",
            "claimNonRevMtp": [
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0"
        ],
            "claimNonRevMtpAuxHi": "0",
            "claimNonRevMtpAuxHv": "0",
            "claimNonRevMtpNoAux": "1",
            "claimSchema": "274380136414749538182079640726762994055",
            "hoIdenState": "15533500893656072595239373534067349826920550354471047383169002073971099943063",
            "id": "70764531162446535095600399295545291100108866293857525238033639063549444096",
            "operator": 1,
            "slotIndex": 2,
            "timestamp": "1641741044",
            "value": "20000101"

    }

        const expOut = {
            challenge: "84239",
            id: "70764531162446535095600399295545291100108866293857525238033639063549444096",
            claimSchema: "274380136414749538182079640726762994055",
            slotIndex: "2",
            operator: "1",
            value: "20000101",
            timestamp: "1641741044",
        }
        const w = await circuit.calculateWitness(inputs, true);

        await circuit.assertOut(w, expOut);
    });

})
;
