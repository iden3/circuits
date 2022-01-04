import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("test claim query", function () {

    this.timeout(600000);

    let circuit;

    before(async function () {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits/examples", "credentialAtomicQuery.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                reduceConstraints: false,
            },
        );

    });

    after(async function () {
        circuit.release()
    })

    it("test query with KYCCountry credential", async () => {
        const inputs = {
            id: "358753682585156032607991143404182618036143329412223697640731109391605432320",
            hoIdenState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",

            authClaimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
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

            authClaimRevTreeRoot: "0",
            authClaimNonRevMtp: ["0", "0", "0", "0"],
            authClaimNonRevMtpNoAux: "1",
            authClaimNonRevMtpAuxHi: "0",
            authClaimNonRevMtpAuxHv: "0",

            authClaimRootsTreeRoot: "0",

            challenge: "1",
            challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",

            claimSchema: "138261091489730249248424379929924548836",
            claim: ["3541084760699114883882170454247606663396", "358753682585156032607991143404182618036143329412223697640731109391605432320", "980", "1", "227737578865723621818874605733", "0", "0", "0"],
            claimIssuanceClaimsTreeRoot: "13731603230335914521442894376919753815007446524287359973379359589880317722784",
            claimIssuanceIdenState: "15836933293307196079102626646704289284946136304980757970414278866777483277967",
            claimIssuanceMtp: ["14229847371519562490394300082490539719533095227665433899280655808527677894054", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            claimIssuanceRevTreeRoot: "0",
            claimIssuanceRootsTreeRoot: "0",

            claimNonRevIssuerClaimsTreeRoot: "13731603230335914521442894376919753815007446524287359973379359589880317722784",
            claimNonRevIssuerRevTreeRoot: "0",
            claimNonRevIssuerRootsTreeRoot: "0",
            claimNonRevIssuerState: "15836933293307196079102626646704289284946136304980757970414278866777483277967",
            claimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            claimNonRevMtpAuxHi: "0",
            claimNonRevMtpAuxHv: "0",
            claimNonRevMtpNoAux: "1",
            operator: 0,
            slotIndex: 2,
            timestamp: "1640251952",
            value: "980"
        }

        const expOut = {
            challenge: "1",
            id: "358753682585156032607991143404182618036143329412223697640731109391605432320",
            hoIdenState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",
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
            hoIdenState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",

            authClaimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
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

            authClaimRevTreeRoot: "0",
            authClaimNonRevMtp: ["0", "0", "0", "0"],
            authClaimNonRevMtpNoAux: "1",
            authClaimNonRevMtpAuxHi: "0",
            authClaimNonRevMtpAuxHv: "0",

            authClaimRootsTreeRoot: "0",

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
            timestamp: "1638533435"
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


})
;
