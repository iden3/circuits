const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");

export {};

describe("idState test: 1 auth claim is in the claims tree. Add 1 more auth claim to the claims tree.", function () {
    this.timeout(600000);

    it("Test IdState: ", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "idState.circom"),
            {
                outputOptions: {
                    basePath: path.join(__dirname, "circuits", "build"),
                    recompile: false,
                },
                reduceConstraints: false,
            },
        );

        let inputs = {
            id: "323416925264666217617288569742564703632850816035761084002720090377353297920",
            oldIdState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",
            newIdState: "6243262098189365110173326120466238114783380459336290130750689570190357902007",

            claimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
            siblingsClaimTree: ["0", "0", "0", "0"],
            claim : [
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
            siblingsRevTree: ["0", "0", "0", "0"],
            revMtpNoAux: "1",
            revMtpAuxHi: "0",
            revMtpAuxHv: "0",

            rootsTreeRoot: "0",

            challenge: "1",
            challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
        };
        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });
});
