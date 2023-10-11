

import { expect } from "chai"
import path from "path";
import { wasm } from "circom_tester";

describe("Test On Chain credentialAtomicQueryMTPOnChain.circom", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {

        circuit = await wasm(
            path.join(__dirname, "../../circuits/", "credentialAtomicQueryMTPV2OnChain.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
            },
        );

    });

    after(async () => {
        circuit.release()
    })
    const basePath = '../../testvectorgen/credentials/onchain/mtpv2/testdata'
    const tests = [
        require(`${basePath}/claimIssuedOnProfileID.json`),
        require(`${basePath}/claimIssuedOnProfileID2.json`),
        require(`${basePath}/claimIssuedOnUserID.json`),
        require(`${basePath}/claimNonMerklized.json`),
        require(`${basePath}/revoked_claim_without_revocation_check.json`)
    ];

    tests.forEach(({ desc, inputs, expOut }) => {
        it(`${desc}`, async function () {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });

    const failTestCase = require(`${basePath}/revoked_claim_with_revocation_check.json`)
    it(failTestCase.desc, async () => {
        const { inputs } = failTestCase

        let error;
        await circuit.calculateWitness(inputs, true).catch((err) => {
            error = err;
        });
        expect(error.message).to.include("Error in template checkClaimNotRevoked");
    });

});
