import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

export {};

describe("credentialAtomicQueryMTPWithRelayTest", function() {

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

    it("credentialAtomicQueryMTPWithRelayTest", async () => {

        const inputs = {
            userAuthClaim: ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
            userAuthClaimMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            userAuthClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            userAuthClaimNonRevMtpAuxHi: "0",
            userAuthClaimNonRevMtpAuxHv: "0",
            userAuthClaimNonRevMtpNoAux: "1",
            userClaimsTreeRoot: "9763429684850732628215303952870004997159843236039795272605841029866455670219",
            userRevTreeRoot: "0",
            userRootsTreeRoot: "0",
            userID: "379949150130214723420589610911161895495647789006649785264738141299135414272",
            challenge: "1",
            challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
            issuerClaim: ["3583233690122716044519380227940806650830", "379949150130214723420589610911161895495647789006649785264738141299135414272", "10", "0", "30803922965249841627828060161", "0", "0", "0"],
            issuerClaimClaimsTreeRoot: "3077200351284676204723270374054827783313480677490603169533924119235084704890",
            issuerClaimIdenState: "18605292738057394742004097311192572049290380262377486632479765119429313092475",
            issuerClaimMtp: ["0", "0", "18337129644116656308842422695567930755039142442806278977230099338026575870840", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            issuerClaimRevTreeRoot: "0",
            issuerClaimRootsTreeRoot: "0",
            issuerClaimNonRevClaimsTreeRoot: "3077200351284676204723270374054827783313480677490603169533924119235084704890",
            issuerClaimNonRevRevTreeRoot: "0",
            issuerClaimNonRevRootsTreeRoot: "0",
            issuerClaimNonRevState: "18605292738057394742004097311192572049290380262377486632479765119429313092475",
            issuerClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            issuerClaimNonRevMtpAuxHi: "0",
            issuerClaimNonRevMtpAuxHv: "0",
            issuerClaimNonRevMtpNoAux: "1",
            claimSchema: "180410020913331409885634153623124536270",
            issuerID: "26599707002460144379092755370384635496563807452878989192352627271768342528",
            operator: 1,
            slotIndex: 2,
            timestamp: "1642074362",
            value: ["10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            relayProofValidClaimsTreeRoot: "8121168901305742662057879845808052431346752743553205352641990714922661618462",
            relayProofValidRevTreeRoot: "0",
            relayProofValidRootsTreeRoot: "0",
            relayState: "4239448240735161374561925497474400621823161116770305241717998726622296721696",
            userStateInRelayClaim: ["795467278703584189433295357807347445218", "379949150130214723420589610911161895495647789006649785264738141299135414272", "0", "0", "0", "0", "18656147546666944484453899241916469544090258810192803949522794490493271005313", "0"],
            userStateInRelayClaimMtp: ["12411413272899006501067884001808071121528224140660538219214791597550929401851", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
        }

        const expOut = {
            challenge: "1",
            userID: "379949150130214723420589610911161895495647789006649785264738141299135414272",
            claimSchema: "180410020913331409885634153623124536270",
            slotIndex: "2",
            operator: "1",
            timestamp: "1642074362",
            issuerID: "26599707002460144379092755370384635496563807452878989192352627271768342528",
        }

        const w = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(w);
        await circuit.assertOut(w, expOut);
    });

});
