const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("auth test", function () {
    this.timeout(600000);

    it("Test Auth", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "auth.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                reduceConstraints: false,
            }
        );

        // input data generated with testvectorgen/go/key-rotation/IdOwnershipBySignature, which uses go-iden3-core
        const inputs = {
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

            state: "18311560525383319719311394957064820091354976310599818797157189568621466950811",
        }

        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });
});
