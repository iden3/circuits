import {expect} from "chai";
import {describe} from "mocha";

const path = require("path");
const wasmTester = require("circom_tester").wasm;

describe("Test credentialAtomicQueryV3OffChain.circom", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasmTester(
            path.join(__dirname, "../../circuits", "credentialAtomicQueryV3.circom"),
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

    const sigBasePath = '../../testvectorgen/credentials/v3/testdata/sig'
    const mtpBasePath = '../../testvectorgen/credentials/v3/testdata/mtp'
    const tests = [
        // sig
        require(`${sigBasePath}/claimIssuedOnProfileID.json`),
        require(`${sigBasePath}/claimIssuedOnProfileID2.json`),
        require(`${sigBasePath}/claimIssuedOnUserID.json`),
        require(`${sigBasePath}/profileID_subject.json`),
        require(`${sigBasePath}/claimNonMerklized.json`),
        require(`${sigBasePath}/claimWithLinkNonce.json`),
        require(`${sigBasePath}/between_operator.json`),
        require(`${sigBasePath}/less_than_eq_operator.json`),
        require(`${sigBasePath}/selective_disclosure.json`),
        require(`${sigBasePath}/nullify_modifier.json`),
        require(`${sigBasePath}/revoked_claim_without_revocation_check.json`),
        require(`${sigBasePath}/jsonld_non_inclusion.json`),

        // mtp
        require(`${mtpBasePath}/claimIssuedOnProfileID.json`),
        require(`${mtpBasePath}/claimIssuedOnProfileID2.json`),
        require(`${mtpBasePath}/claimIssuedOnUserID.json`),
        require(`${mtpBasePath}/profileID_subject.json`),
        require(`${mtpBasePath}/claimNonMerklized.json`),
        require(`${mtpBasePath}/claimWithLinkNonce.json`),
        require(`${mtpBasePath}/between_operator.json`),
        require(`${mtpBasePath}/less_than_eq_operator.json`),
        require(`${mtpBasePath}/selective_disclosure.json`),
        require(`${mtpBasePath}/nullify_modifier.json`),
        require(`${mtpBasePath}/revoked_claim_without_revocation_check.json`),
    ];

    tests.forEach(({ desc, inputs, expOut }) => {
        it(`${desc}`, async function () {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });

    const failTestCase = [
        require(`${sigBasePath}/revoked_claim_with_revocation_check.json`),
        require(`${mtpBasePath}/revoked_claim_with_revocation_check.json`),
    ]

    failTestCase.forEach(({ desc, inputs, expOut }) => {
        it(`${desc}`, async function () {
            let error;
            await circuit.calculateWitness(inputs, true).catch((err) => {
                error = err;
            });
            expect(error.message).to.include("Error in template checkClaimNotRevoked");
        })
    });
});
