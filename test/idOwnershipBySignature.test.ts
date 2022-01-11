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
            path.join(__dirname, "circuits", "idOwnershipBySignatures.circom"),
            {reduceConstraints: false}
        );
    });

    it("Ownership should be ok. Auth claims total: 1. Signed by: 1st claim. Revoked: none", async () => {
        const inputs = {
            hoIdenState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",

            claimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
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
            hoIdenState: "6243262098189365110173326120466238114783380459336290130750689570190357902007",

            claimsTreeRoot: "15354310380648059701373215284168790999686007389864108825597474513976128684735",
            authClaimMtp: ["14501975351413460283779241106398661838785725538630637996477950952692691051377", "0", "0", "0"],
            authClaim : [
                "251025091000101825075425831481271126140",
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
            hoIdenState: "21766477599468142028922103113527130977705138013698789903179651260910260107586",

            claimsTreeRoot: "15354310380648059701373215284168790999686007389864108825597474513976128684735",
            authClaimMtp: ["14501975351413460283779241106398661838785725538630637996477950952692691051377", "0", "0", "0"],
            authClaim : [
                "251025091000101825075425831481271126140",
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
            hoIdenState: "14259000198854891184065240409087970244942582321666208572498086205906796945878",

            claimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
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

        let error;
        await circuit.calculateWitness(inputs, true).catch((err) => {
            error = err;
        });
        expect(error).not.to.be.undefined
        expect(error.message).to.include("Error: Assert Failed. Error in template")
    });

    it(`Ownership should fail. Claims total: 2. Signed by: 2nd claim. Revoked: 2nd claim`, async () => {

        const inputs = {
            hoIdenState: "16747519459565752629047138551807347113144675856294452502987443819850627139518",

            claimsTreeRoot: "15354310380648059701373215284168790999686007389864108825597474513976128684735",
            authClaimMtp: ["14501975351413460283779241106398661838785725538630637996477950952692691051377", "0", "0", "0"],
            authClaim : [
                "251025091000101825075425831481271126140",
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
        expect(error).not.to.be.undefined
        expect(error.message).to.include("Error: Assert Failed. Error in template")
    });
});
