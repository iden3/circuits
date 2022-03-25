const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const expect = chai.expect;

export {};

describe("idOwnershipBySignature", function() {
    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await tester(
            path.join(__dirname, "../circuits", "idOwnershipBySignatures.circom"),
            {
                output: path.join(__dirname, "../circuits", "build/idOwnershipBySignatures"),
                recompile: true,
                reduceConstraints: false,
            },
        );
    });

    it("Ownership should be ok. Auth claims total: 1. Signed by: 1st claim. Revoked: none", async () => {
        const inputs = {
            hoIdenState: "5816868615164565912277677884704888703982258184820398645933682814085602171910",

            claimsTreeRoot: "8033159210005724351649063848617878571712113104821846241291681963936214187701",
            authClaimMtp: ["0", "0", "0", "0"],
            authClaim : [
                "269270088098491255471307608775043319525",
                "0",
                "17640206035128972995519606214765283372613874593503528180869261482403155458945",
                "20634138280259599560273310290025659992320584624461316485434108770067472477956",
                "15930428023331155902",
                "0",
                "0",
                "0",
            ],

            revTreeRoot: "0",
            authClaimNonRevMtp: ["0", "0", "0", "0"],
            authClaimNonRevMtpNoAux: "1",
            authClaimNonRevMtpAuxHi: "0",
            authClaimNonRevMtpAuxHv: "0",

            rootsTreeRoot: "0",

            challenge: "1",
            challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
        }

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
    });

    it(`Ownership should be ok. Claims total: 2. Signed by: 2nd claim. Revoked: none`, async () => {
        const inputs = {
            hoIdenState: "21799818405085739943263537616587664863501401321957145427557061721281929782461",

            claimsTreeRoot: "1267420139493013179506222700019094822263769414097067662137215579894068836606",
            authClaimMtp: ["8033159210005724351649063848617878571712113104821846241291681963936214187701", "0", "0", "0"],
            authClaim : [
                "269270088098491255471307608775043319525",
                "0",
                "4720763745722683616702324599137259461509439547324750011830105416383780791263",
                "4844030361230692908091131578688419341633213823133966379083981236400104720538",
                "16547485850637761685",
                "0",
                "0",
                "0",
            ],

            revTreeRoot: "0",
            authClaimNonRevMtp: ["0", "0", "0", "0"],
            authClaimNonRevMtpNoAux: "1",
            authClaimNonRevMtpAuxHi: "0",
            authClaimNonRevMtpAuxHv: "0",

            rootsTreeRoot: "0",

            challenge: "1",
            challengeSignatureR8x: "3318605682427930847043923964996627571509054270532204838981931388121839601904",
            challengeSignatureR8y: "6885828942356963641443098413925008636428756893590364657052219244852107012379",
            challengeSignatureS: "1239257276045842588253148642684748186882810960469506371777432113478495615573",
        }

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
    });

    it(`Ownership should be ok. Claims total: 2. Signed by: 2nd claim. Revoked: 1st claim`, async () => {

        const inputs = {
            hoIdenState: "16212306690062253699959504587205358109947105302123737824933420422652535404326",

            claimsTreeRoot: "1267420139493013179506222700019094822263769414097067662137215579894068836606",
            authClaimMtp: ["8033159210005724351649063848617878571712113104821846241291681963936214187701", "0", "0", "0"],
            authClaim : [
                "269270088098491255471307608775043319525",
                "0",
                "4720763745722683616702324599137259461509439547324750011830105416383780791263",
                "4844030361230692908091131578688419341633213823133966379083981236400104720538",
                "16547485850637761685",
                "0",
                "0",
                "0",
            ],

            revTreeRoot: "9572161194792737168173461511232528826921561251689921703982232129896045083154",
            authClaimNonRevMtp: ["0", "0", "0", "0"],
            authClaimNonRevMtpNoAux: "0",
            authClaimNonRevMtpAuxHi: "15930428023331155902",
            authClaimNonRevMtpAuxHv: "0",

            rootsTreeRoot: "0",

            challenge: "1",
            challengeSignatureR8x: "3318605682427930847043923964996627571509054270532204838981931388121839601904",
            challengeSignatureR8y: "6885828942356963641443098413925008636428756893590364657052219244852107012379",
            challengeSignatureS: "1239257276045842588253148642684748186882810960469506371777432113478495615573",
        }

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
    });

    it(`Ownership should fail. Claims total: 1. Signed by: 1st claim. Revoked: 1st claim`, async () => {

        const inputs = {
            hoIdenState: "13312337630407117190690801285857799236101280464600310314935537176326743082698",

            claimsTreeRoot: "8033159210005724351649063848617878571712113104821846241291681963936214187701",
            authClaimMtp: ["0", "0", "0", "0"],
            authClaim : [
                "269270088098491255471307608775043319525",
                "0",
                "17640206035128972995519606214765283372613874593503528180869261482403155458945",
                "20634138280259599560273310290025659992320584624461316485434108770067472477956",
                "15930428023331155902",
                "0",
                "0",
                "0",
            ],

            revTreeRoot: "9572161194792737168173461511232528826921561251689921703982232129896045083154",
            authClaimNonRevMtp: ["0", "0", "0", "0"],
            authClaimNonRevMtpNoAux: "1",
            authClaimNonRevMtpAuxHi: "0",
            authClaimNonRevMtpAuxHv: "0",

            rootsTreeRoot: "0",

            challenge: "1",
            challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
        }

        // let error;
        let error;
        await circuit.calculateWitness(inputs, true).catch((err) => {
            error = err;
        });

        expect(error.message).to.include("Error: Assert Failed. Error in template")
    });

    it(`Ownership should fail. Claims total: 2. Signed by: 2nd claim. Revoked: 2nd claim`, async () => {

        const inputs = {
            hoIdenState: "20138099233809816912157444795305418523517739598699803427285545016792186731290",

            claimsTreeRoot: "1267420139493013179506222700019094822263769414097067662137215579894068836606",
            authClaimMtp: ["8033159210005724351649063848617878571712113104821846241291681963936214187701", "0", "0", "0"],
            authClaim : [
                "269270088098491255471307608775043319525",
                "0",
                "4720763745722683616702324599137259461509439547324750011830105416383780791263",
                "4844030361230692908091131578688419341633213823133966379083981236400104720538",
                "16547485850637761685",
                "0",
                "0",
                "0",
            ],

            revTreeRoot: "19457836367977756683788174626344746000647215586327462959978582532138667631896",
            authClaimNonRevMtp: ["9572161194792737168173461511232528826921561251689921703982232129896045083154", "0", "0", "0"],
            authClaimNonRevMtpNoAux: "1",
            authClaimNonRevMtpAuxHi: "0",
            authClaimNonRevMtpAuxHv: "0",

            rootsTreeRoot: "0",

            challenge: "1",
            challengeSignatureR8x: "3318605682427930847043923964996627571509054270532204838981931388121839601904",
            challengeSignatureR8y: "6885828942356963641443098413925008636428756893590364657052219244852107012379",
            challengeSignatureS: "1239257276045842588253148642684748186882810960469506371777432113478495615573",
        }

        let error;
        await circuit.calculateWitness(inputs, true).catch((err) => {
            error = err;
        });
        expect(error.message).to.include("Error: Assert Failed. Error in template")
    });
});
