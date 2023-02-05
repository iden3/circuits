import { expect } from "chai"
import path from "path";
import { wasm } from "circom_tester";

describe("On Chain: Test credentialAtomicQuerySigOnChain.circom", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasm(
            path.join(__dirname, "../../circuits", "credentialAtomicQuerySigOnChain.circom"),
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

    const basePath = '../../testvectorgen/credentials/onchain/sigv2/testdata'
    const tests = [

        require(`${basePath}/jsonld_non_inclusion.json`),
        require(`${basePath}/profileID_subject_profileID2.json`),
        require(`${basePath}/profileID_subject_userid.json`),
        require(`${basePath}/profileID_subject.json`),
        require(`${basePath}/regular_claim.json`),
        require(`${basePath}/revoked_claim_without_revocation_check.json`),
        require(`${basePath}/userID_subject.json`)
    ];

    tests.forEach(({ desc, inputs, expOut }) => {
        it(`${desc}`, async function () {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });

    const failTestCase = require(`${basePath}/revoked_claim_with_revocation_check.json`);
    it(failTestCase.desc, async () => {
        const { inputs } = failTestCase

        let error;
        await circuit.calculateWitness(inputs, true).catch((err) => {
            error = err;
        });
        expect(error.message).to.include("Error in template checkClaimNotRevoked");
    });
});
