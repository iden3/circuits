const path = require("path");
const tester = require("circom_tester").wasm;

export {};

const inputs1JSON = {
    hoId: "323416925264666217617288569742564703632850816035761084002720090377353297920",
    hoIdenState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",

    hoClaimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
    hoAuthClaimMtp: ["0", "0", "0", "0"],
    hoAuthClaim : [
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
    hoAuthClaimNonRevMtp: ["0", "0", "0", "0"],
    hoAuthClaimNonRevMtpNoAux: "1",
    hoAuthClaimNonRevMtpAuxHv: "0",
    hoAuthClaimNonRevMtpAuxHi: "0",

    hoRootsTreeRoot: "0",

    hoChallenge: "1",
    hoChallengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
    hoChallengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
    hoChallengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",

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
    isProofExistClaimsTreeRoot: "12573770502003146461465546300779188853443126236634097100553384625068680144727",
    isProofExistMtp: [
      "1661463092807197273156924399324947871308508349434725136548748083220432380465",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
    ],

    isProofValidClaimsTreeRoot: "12573770502003146461465546300779188853443126236634097100553384625068680144727",

    isProofValidRevTreeRoot: "0",
    isProofValidNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0"],
    isProofValidNonRevMtpNoAux: "1",
    isProofValidNonRevMtpAuxHi: "0",
    isProofValidNonRevMtpAuxHv: "0",

    isProofValidRootsTreeRoot: "2086215205011362860076637504288147727370020720598964230062199595376996763261",
    isProofRootMtp: ["0", "0", "0", "0", "0", "0", "0", "0"],

    isIdenState: "1582110369618327882141504845095711793245222583864390435069712051135983166472",
};

describe("credential test (old)", function() {
    this.timeout(600000);

    it("Test Credential", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "credential.circom"),
            {
              output: path.join(__dirname, "circuits", "build"),
              recompile: true,
              reduceConstraints: false,
            },
        );

        const witness1 = await circuit.calculateWitness(inputs1JSON);
        await circuit.checkConstraints(witness1);

        // const witness2 = await circuit.calculateWitness(JSON.parse(inputs2JSON));
        // await circuit.checkConstraints(witness2);
    });
});
