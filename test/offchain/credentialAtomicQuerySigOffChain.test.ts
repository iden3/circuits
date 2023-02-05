import {describe} from "mocha";

const path = require("path");
const wasmTester = require("circom_tester").wasm;
const chai = require("chai");
const expect = chai.expect;

describe("Test credentialAtomicQuerySigOffChain.circom", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasmTester(
            path.join(__dirname, "../../circuits", "credentialAtomicQuerySigOffChain.circom"),
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

    const basePath = '../../testvectorgen/credentials/sigv2/testdata'
    const tests = [
        require(`${basePath}/jsonld_non_inclusion.json`),
        require(`${basePath}/profileID_subject.json`),
        require(`${basePath}/profileID_subject_profileID2.json`),
        require(`${basePath}/profileID_subject_userid.json`),
        require(`${basePath}/regular_claim.json`),
        require(`${basePath}/revoked_claim_with_revocation_check.json`),
        require(`${basePath}/revoked_claim_without_revocation_check.json`),
        require(`${basePath}/userID_subject.json`)
    ];

    tests.forEach(({desc, inputs, expOut}) => {
        it(`${desc}`, async function () {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });


    it("Checking revoked status when claim is revoked (Sig)", async () => {
        const inputs = {
            "requestID": "23",
            "userGenesisID": "23148936466334350744548790012294489365207440754509988986684797708370051073",
            "profileNonce": "0",
            "claimSubjectProfileNonce": "0",
            "issuerID": "21933750065545691586450392143787330185992517860945727248803138245838110721",
            "issuerClaim": [
                "3583233690122716044519380227940806650830",
                "23148936466334350744548790012294489365207440754509988986684797708370051073",
                "10",
                "0",
                "30803922965249841627828060161",
                "0",
                "0",
                "0"
            ],
            "issuerClaimNonRevClaimsTreeRoot": "20643387758736831799596675626240785455902781070167728593409367019626753600795",
            "issuerClaimNonRevRevTreeRoot": "19374975721259875597650302716689543547647001662517455822229477759190533109280",
            "issuerClaimNonRevRootsTreeRoot": "0",
            "issuerClaimNonRevState": "20420704177203139055971454163395877029462021737850567671726924780413332537",
            "issuerClaimNonRevMtp": [
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
            "issuerClaimNonRevMtpAuxHi": "0",
            "issuerClaimNonRevMtpAuxHv": "0",
            "issuerClaimNonRevMtpNoAux": "0",
            "claimSchema": "180410020913331409885634153623124536270",
            "issuerClaimSignatureR8x": "6009541096871527792243386384096231340067474190101091530507148551135935669869",
            "issuerClaimSignatureR8y": "21407298901003665469054234025891175478757417093942142815529365365949388290718",
            "issuerClaimSignatureS": "1061441685873832236639155829779552898548912415538872104865210006348646647963",
            "issuerAuthClaim": [
                "80551937543569765027552589160822318028",
                "0",
                "18843627616807347027405965102907494712213509184168391784663804560181782095821",
                "21769574296201138406688395494914474950554632404504713590270198507141791084591",
                "17476719578317212277",
                "0",
                "0",
                "0"
            ],
            "issuerAuthClaimMtp": [
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
            "issuerAuthClaimNonRevMtp": [
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
            "issuerAuthClaimNonRevMtpAuxHi": "1",
            "issuerAuthClaimNonRevMtpAuxHv": "0",
            "issuerAuthClaimNonRevMtpNoAux": "0",
            "issuerAuthClaimsTreeRoot": "20643387758736831799596675626240785455902781070167728593409367019626753600795",
            "issuerAuthRevTreeRoot": "19374975721259875597650302716689543547647001662517455822229477759190533109280",
            "issuerAuthRootsTreeRoot": "0",
            "claimPathNotExists": "0",
            "claimPathMtp": [
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
            "claimPathMtpNoAux": "0",
            "claimPathMtpAuxHi": "0",
            "claimPathMtpAuxHv": "0",
            "claimPathKey": "0",
            "claimPathValue": "0",
            "operator": 1,
            "slotIndex": 2,
            "timestamp": "1642074362",
            "isRevocationChecked": 1,
            "value": [
                "10",
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
            ]
        };

        let error;
        await circuit.calculateWitness(inputs, true).catch((err) => {
            error = err;
        });
        expect(error.message).to.include("Error in template checkClaimNotRevoked");
    });
});
