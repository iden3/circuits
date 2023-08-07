import {describe} from "mocha";

const path = require("path");
const wasmTester = require("circom_tester").wasm;
const chai = require("chai");

describe("Test credentialAtomicQuerySigMTPOffChain.circom", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasmTester(
            path.join(__dirname, "../../circuits", "credentialAtomicQuerySigMTP.circom"),
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

    const sigBasePath = '../../testvectorgen/credentials/sigmtp/sig/testdata'
    const mtpBasePath = '../../testvectorgen/credentials/sigmtp/mtp/testdata'
    const tests = [
        // sig
        require(`${sigBasePath}/jsonld_non_inclusion.json`),
        require(`${sigBasePath}/profileID_subject.json`),
        require(`${sigBasePath}/profileID_subject_profileID2.json`),
        require(`${sigBasePath}/profileID_subject_userid.json`),
        require(`${sigBasePath}/regular_claim.json`),
        // require(`${sigBasePath}/revoked_claim_with_revocation_check.json`),
        require(`${sigBasePath}/revoked_claim_without_revocation_check.json`),
        require(`${sigBasePath}/userID_subject.json`),

        // mtp
        require(`${mtpBasePath}/claimIssuedOnProfileID.json`),
        require(`${mtpBasePath}/claimIssuedOnProfileID2.json`),
        require(`${mtpBasePath}/claimIssuedOnUserID.json`),
        require(`${mtpBasePath}/claimNonMerklized.json`),
        // require(`${basePath}/revoked_claim_with_revocation_check.json`),
        require(`${mtpBasePath}/revoked_claim_without_revocation_check.json`)
    ];

    tests.forEach(({desc, inputs, expOut}) => {
        it(`${desc}`, async function () {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });
});
