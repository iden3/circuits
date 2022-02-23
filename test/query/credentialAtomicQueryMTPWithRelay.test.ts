import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("Test claim query IN, NOT IN operation", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits/query", "credentialAtomicQueryMTPWithRelayTest.circom"),
            {
                output: path.join(__dirname, "../circuits", "build", "credentialAtomicQueryMTPWithRelayTest"),
                recompile: true,
                reduceConstraints: false,
            },
        );
    });

    after(async () => {
        circuit.release()
    })

    it("claims slot[3] = `0`, value NOT IN the list: [1, 12, 13, 14]", async () => {

        const inputs = {
            id: "323416925264666217617288569742564703632850816035761084002720090377353297920",

            reIdenState: "9567295008641054288261061367762855120424889358077873428998243939488311767955",
            hoStateInRelayClaimMtp: ["0", "14984182005329191396993118103366240378691291400560637634045002581903516328103", "0", "0"],
            hoStateInRelayClaim: ["928251232571379559706167670634346311933", "323416925264666217617288569742564703632850816035761084002720090377353297920", "0", "0", "0", "0", "18311560525383319719311394957064820091354976310599818797157189568621466950811", "0"],
            reProofValidClaimsTreeRoot: "4363126336135379650861073572245208647463603543037672666254113932136121452383",
            reProofValidRevTreeRoot: "0",
            reProofValidRootsTreeRoot: "0",

            hoClaimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
            authClaimMtp: ["0", "0", "0", "0"],
            authClaim: [
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

            challenge: "12345",
            challengeSignatureR8x: "20325325089801048194045249505428880076655971734013328186061936404000070227397",
            challengeSignatureR8y: "18815569172670647983375380394348184587943022270001377870165118142840803131488",
            challengeSignatureS: "2734186134966121487318208483392534525958774516483672794477055935442067869952",

            claimSchema: "49",
            claim: [
                "3402823669209384634633746074317682114609",
                "323416925264666217617288569742564703632850816035761084002720090377353297920",
                "10",
                "0",
                "30803922965249841627828060161",
                "0",
                "0",
                "0",
            ],
            claimIssuanceMtp: [
                "1661463092807197273156924399324947871308508349434725136548748083220432380465",
                "0",
                "0",
                "0",
            ],
            claimIssuanceClaimsTreeRoot: "12573770502003146461465546300779188853443126236634097100553384625068680144727",
            claimIssuanceRevTreeRoot: "0",
            claimIssuanceRootsTreeRoot: "0",
            claimIssuanceIdenState: "7975264883428048087779530852762154205241399157454485265065477883800267795520",
            issuerID: "284566762428324726989704087792235500378284127405663309435086666644619722752",

            claimNonRevMtp: ["0", "0", "0", "0"],
            claimNonRevMtpNoAux: "1",
            claimNonRevMtpAuxHi: "0",
            claimNonRevMtpAuxHv: "0",
            claimNonRevIssuerClaimsTreeRoot: "8493003494726860300633431973273122808125771868287442027245563585092434039664",
            claimNonRevIssuerRevTreeRoot: "0",
            claimNonRevIssuerRootsTreeRoot: "0",
            claimNonRevIssuerState: "7250774806265342444670050834809653548010854890881205160371587352728471237096",

            slotIndex: "3",
            value: ["1", "12", "13", "14"],
            operator: "4",
            timestamp: "1638533435",
        }

        const expOut = {
            challenge: "12345",
            id: "323416925264666217617288569742564703632850816035761084002720090377353297920",
            claimSchema: "49",
            slotIndex: "3",
            operator: "4",
            timestamp: "1638533435",
            issuerID: "284566762428324726989704087792235500378284127405663309435086666644619722752",
        }

        const w = await circuit.calculateWitness(inputs, true);
        await circuit.assertOut(w, expOut);
    });

    it("claims slot[3] = `0`, value IN the list: [1, 0, 13, 14]", async () => {
        const inputs = {
            id: "323416925264666217617288569742564703632850816035761084002720090377353297920",

            reIdenState: "9567295008641054288261061367762855120424889358077873428998243939488311767955",
            hoStateInRelayClaimMtp: ["0", "14984182005329191396993118103366240378691291400560637634045002581903516328103", "0", "0"],
            hoStateInRelayClaim: ["928251232571379559706167670634346311933", "323416925264666217617288569742564703632850816035761084002720090377353297920", "0", "0", "0", "0", "18311560525383319719311394957064820091354976310599818797157189568621466950811", "0"],
            reProofValidClaimsTreeRoot: "4363126336135379650861073572245208647463603543037672666254113932136121452383",
            reProofValidRevTreeRoot: "0",
            reProofValidRootsTreeRoot: "0",

            hoClaimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
            authClaimMtp: ["0", "0", "0", "0"],
            authClaim: [
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

            challenge: "12345",
            challengeSignatureR8x: "20325325089801048194045249505428880076655971734013328186061936404000070227397",
            challengeSignatureR8y: "18815569172670647983375380394348184587943022270001377870165118142840803131488",
            challengeSignatureS: "2734186134966121487318208483392534525958774516483672794477055935442067869952",

            claimSchema: "49",
            claim: [
                "3402823669209384634633746074317682114609",
                "323416925264666217617288569742564703632850816035761084002720090377353297920",
                "10",
                "0",
                "30803922965249841627828060161",
                "0",
                "0",
                "0",
            ],
            claimIssuanceMtp: [
                "1661463092807197273156924399324947871308508349434725136548748083220432380465",
                "0",
                "0",
                "0",
            ],
            claimIssuanceClaimsTreeRoot: "12573770502003146461465546300779188853443126236634097100553384625068680144727",
            claimIssuanceRevTreeRoot: "0",
            claimIssuanceRootsTreeRoot: "0",
            claimIssuanceIdenState: "7975264883428048087779530852762154205241399157454485265065477883800267795520",
            issuerID: "284566762428324726989704087792235500378284127405663309435086666644619722752",

            claimNonRevMtp: ["0", "0", "0", "0"],
            claimNonRevMtpNoAux: "1",
            claimNonRevMtpAuxHi: "0",
            claimNonRevMtpAuxHv: "0",
            claimNonRevIssuerClaimsTreeRoot: "8493003494726860300633431973273122808125771868287442027245563585092434039664",
            claimNonRevIssuerRevTreeRoot: "0",
            claimNonRevIssuerRootsTreeRoot: "0",
            claimNonRevIssuerState: "7250774806265342444670050834809653548010854890881205160371587352728471237096",

            slotIndex: "3",
            value: ["1", "0", "13", "14"],
            operator: "3",
            timestamp: "1638533435",
        }

        const expOut = {
            challenge: "12345",
            id: "323416925264666217617288569742564703632850816035761084002720090377353297920",
            claimSchema: "49",
            slotIndex: "3",
            operator: "3",
            timestamp: "1638533435",
            issuerID: "284566762428324726989704087792235500378284127405663309435086666644619722752",
        }
        const w = await circuit.calculateWitness(inputs, true);

        await circuit.assertOut(w, expOut);
    });
});
