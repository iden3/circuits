const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const expect = chai.expect;

export {};

describe("idOwnershipBySignature", function () {
    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await tester(
            path.join(__dirname, "../circuits", "idOwnershipBySignatureTest.circom"),
            {
                output: path.join(__dirname, "../circuits", "build/idOwnershipBySignature"),
                recompile: false,
                reduceConstraints: false,
            },
        );
    });

    it("Ownership should be ok. Auth claims total: 1. Signed by: 1st claim. Revoked: none", async () => {
        const inputs = {
            "challenge": "1",
            "challengeSignatureR8x": "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            "challengeSignatureR8y": "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            "challengeSignatureS": "2093461910575977345603199789919760192811763972089699387324401771367839603655",
            "userAuthClaim": ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
            "userAuthClaimMtp": ["0", "0", "0", "0"],
            "userAuthClaimNonRevMtp": ["0", "0", "0", "0"],
            "userAuthClaimNonRevMtpAuxHi": "0",
            "userAuthClaimNonRevMtpAuxHv": "0",
            "userAuthClaimNonRevMtpNoAux": "1",
            "userClaimsTreeRoot": "9763429684850732628215303952870004997159843236039795272605841029866455670219",
            "userRevTreeRoot": "0",
            "userRootsTreeRoot": "0",
            "userState": "18656147546666944484453899241916469544090258810192803949522794490493271005313"
        }

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
    });

    it(`Ownership should be ok. Claims total: 2. Signed by: 2nd claim. Revoked: none`, async () => {
        const inputs = {
            "challenge": "1",
            "challengeSignatureR8x": "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            "challengeSignatureR8y": "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            "challengeSignatureS": "2093461910575977345603199789919760192811763972089699387324401771367839603655",
            "userAuthClaim": ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
            "userAuthClaimMtp": ["16935233905999379395228879484629933212061337894505747058350106225580401780334", "0", "0", "0"],
            "userAuthClaimNonRevMtp": ["0", "0", "0", "0"],
            "userAuthClaimNonRevMtpAuxHi": "0",
            "userAuthClaimNonRevMtpAuxHv": "0",
            "userAuthClaimNonRevMtpNoAux": "1",
            "userClaimsTreeRoot": "13140014475758763008111388434617161215041882690796230451685700392789570848755",
            "userRevTreeRoot": "0",
            "userRootsTreeRoot": "0",
            "userState": "8061408109549794622894897529509400209321866093562736009325703847306244896707"
        }

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
    });

    it(`Ownership should be ok. Claims total: 2. Signed by: 2nd claim. Revoked: 1st claim`, async () => {

        const inputs = {
            "challenge": "1",
            "challengeSignatureR8x": "3318605682427930847043923964996627571509054270532204838981931388121839601904",
            "challengeSignatureR8y": "6885828942356963641443098413925008636428756893590364657052219244852107012379",
            "challengeSignatureS": "1239257276045842588253148642684748186882810960469506371777432113478495615573",
            "userAuthClaim": ["304427537360709784173770334266246861770","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],
            "userAuthClaimMtp": ["9763429684850732628215303952870004997159843236039795272605841029866455670219","0","0","0"],
            "userAuthClaimNonRevMtp": ["0","0","0","0"],
            "userAuthClaimNonRevMtpAuxHi": "15930428023331155902",
            "userAuthClaimNonRevMtpAuxHv": "0",
            "userAuthClaimNonRevMtpNoAux": "0",
            "userClaimsTreeRoot": "13140014475758763008111388434617161215041882690796230451685700392789570848755",
            "userRevTreeRoot": "9572161194792737168173461511232528826921561251689921703982232129896045083154",
            "userRootsTreeRoot": "0",
            "userState": "18455503381966780544107548444536568465272615275508666835914595061438390441982"
        };

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
    });

    /** TODO: this two tests should be reworked, they are not properly test the functionality, C++ version of circom supports proper error handling
     it(`Ownership should fail. Claims total: 1. Signed by: 1st claim. Revoked: 1st claim`, async () => {

        const inputs = {
            userState: "13312337630407117190690801285857799236101280464600310314935537176326743082698",

            userClaimsTreeRoot: "8033159210005724351649063848617878571712113104821846241291681963936214187701",
            userAuthClaimMtp: ["0", "0", "0", "0"],
            userAuthClaim : [
                "269270088098491255471307608775043319525",
                "0",
                "17640206035128972995519606214765283372613874593503528180869261482403155458945",
                "20634138280259599560273310290025659992320584624461316485434108770067472477956",
                "15930428023331155902",
                "0",
                "0",
                "0",
            ],

            userRevTreeRoot: "9572161194792737168173461511232528826921561251689921703982232129896045083154",
            userAuthClaimNonRevMtp: ["0", "0", "0", "0"],
            userAuthClaimNonRevMtpNoAux: "1",
            userAuthClaimNonRevMtpAuxHi: "0",
            userAuthClaimNonRevMtpAuxHv: "0",

            userRootsTreeRoot: "0",

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
            userState: "20138099233809816912157444795305418523517739598699803427285545016792186731290",

            userClaimsTreeRoot: "1267420139493013179506222700019094822263769414097067662137215579894068836606",
            userAuthClaimMtp: ["8033159210005724351649063848617878571712113104821846241291681963936214187701", "0", "0", "0"],
            userAuthClaim : [
                "269270088098491255471307608775043319525",
                "0",
                "4720763745722683616702324599137259461509439547324750011830105416383780791263",
                "4844030361230692908091131578688419341633213823133966379083981236400104720538",
                "16547485850637761685",
                "0",
                "0",
                "0",
            ],

            userRevTreeRoot: "19457836367977756683788174626344746000647215586327462959978582532138667631896",
            userAuthClaimNonRevMtp: ["9572161194792737168173461511232528826921561251689921703982232129896045083154", "0", "0", "0"],
            userAuthClaimNonRevMtpNoAux: "1",
            userAuthClaimNonRevMtpAuxHi: "0",
            userAuthClaimNonRevMtpAuxHv: "0",

            userRootsTreeRoot: "0",

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
     */
});
