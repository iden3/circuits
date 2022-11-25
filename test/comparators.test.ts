const path = require("path");
const tester = require("circom_tester").wasm;

export {};

describe("comparator test", function () {
    this.timeout(200000);

    it("LessThan254", async () => {
        const circuit = await tester(
                    path.join(__dirname, "circuits", "comparators.circom"),
                    { reduceConstraints: false }
        );

        var witness = await circuit.calculateWitness({
            in: ["21888242871839275222246405745257275088548364400416034343698204186575808495616", "2"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});

        witness = await circuit.calculateWitness({
            in: ["2", "21888242871839275222246405745257275088548364400416034343698204186575808495616"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});
        
        witness = await circuit.calculateWitness({
            in: ["21888242871839275222246405745257275088548364400416034343698204186575808495616", "21888242871839275222246405745257275088548364400416034343698204186575808495616"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});

        witness = await circuit.calculateWitness({
            in: ["21888242871839275222246405745257275088548364400416034343698204186575808495615", "21888242871839275222246405745257275088548364400416034343698204186575808495616"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});

        witness = await circuit.calculateWitness({
            in: ["14700167578956157622133035206181082051684666022005149731571763594754596536320", "14813245791101974219226366246228628836697624991405189344891546391637324201984"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});

        witness = await circuit.calculateWitness({
            in: ["21711016745476759975494879586462490265997937461626177968668583242035516932096", "14474011174884484428309352972086249796923471088432928821837627361816848891904"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});

        // high part greater, low part equal
        witness = await circuit.calculateWitness({
            in: ["14474011174884484428309352972086249796923471088432928821837627361816848891904", "7237005597552222214336166409043255556094097046830393569371528361322278289408"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});

        // high part less, low part less
        witness = await circuit.calculateWitness({
            in: ["7237005584072248880760846511709748012584281710011821358101242120770473164800", "14474011168144497761521693023419496025168563420023642716202484241540946329600"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});
        // high part less, low part equal
        witness = await circuit.calculateWitness({
            in: ["7237005584072248880760846511709748012584281710011821358101242120770473164800", "14474011161404511094734033074752742253413655751614356610567341121265043767296"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});
        // high part less, low part greater
        witness = await circuit.calculateWitness({
            in: ["7237005590812235547548506460376501784339189378421107463736385241046375727104", "14474011161404511094734033074752742253413655751614356610567341121265043767296"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});

        // high part equal, low part less
        witness = await circuit.calculateWitness({
            in: ["14474011161404511094734033074752742253413655751614356610567341121265043767296", "14474011168144497761521693023419496025168563420023642716202484241540946329600"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});
        // high part equal, low part equal
        witness = await circuit.calculateWitness({
            in: ["14474011161404511094734033074752742253413655751614356610567341121265043767296", "14474011161404511094734033074752742253413655751614356610567341121265043767296"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});
        // high part equal, low part greater
        witness = await circuit.calculateWitness({
            in: ["14474011168144497761521693023419496025168563420023642716202484241540946329600", "14474011161404511094734033074752742253413655751614356610567341121265043767296"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});

        // high part greater, low part less
        witness = await circuit.calculateWitness({
            in: ["14474011161404511094734033074752742253413655751614356610567341121265043767296", "7237005590812235547548506460376501784339189378421107463736385241046375727104"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});
        // high part greater, low part equal
        witness = await circuit.calculateWitness({
            in: ["14474011161404511094734033074752742253413655751614356610567341121265043767296", "7237005584072248880760846511709748012584281710011821358101242120770473164800"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});
        // high part greater, low part greater
        witness = await circuit.calculateWitness({
            in: ["14474011168144497761521693023419496025168563420023642716202484241540946329600", "7237005584072248880760846511709748012584281710011821358101242120770473164800"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});
    });

    it("GreaterThan254", async () => {
        const circuit = await tester(
                    path.join(__dirname, "circuits", "comparators_greater_than.circom"),
                    { reduceConstraints: false }
        );

        var witness = await circuit.calculateWitness({
            in: ["21888242871839275222246405745257275088548364400416034343698204186575808495616", "2"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});

        witness = await circuit.calculateWitness({
            in: ["2", "21888242871839275222246405745257275088548364400416034343698204186575808495616"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});
        
        witness = await circuit.calculateWitness({
            in: ["21888242871839275222246405745257275088548364400416034343698204186575808495616", "21888242871839275222246405745257275088548364400416034343698204186575808495616"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});

        witness = await circuit.calculateWitness({
            in: ["21888242871839275222246405745257275088548364400416034343698204186575808495615", "21888242871839275222246405745257275088548364400416034343698204186575808495616"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});

        witness = await circuit.calculateWitness({
            in: ["14700167578956157622133035206181082051684666022005149731571763594754596536320", "14813245791101974219226366246228628836697624991405189344891546391637324201984"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});

        witness = await circuit.calculateWitness({
            in: ["21711016745476759975494879586462490265997937461626177968668583242035516932096", "14474011174884484428309352972086249796923471088432928821837627361816848891904"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});

        // high part greater, low part equal
        witness = await circuit.calculateWitness({
            in: ["14474011174884484428309352972086249796923471088432928821837627361816848891904", "7237005597552222214336166409043255556094097046830393569371528361322278289408"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});

        // high part less, low part less
        witness = await circuit.calculateWitness({
            in: ["7237005584072248880760846511709748012584281710011821358101242120770473164800", "14474011168144497761521693023419496025168563420023642716202484241540946329600"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});
        // high part less, low part equal
        witness = await circuit.calculateWitness({
            in: ["7237005584072248880760846511709748012584281710011821358101242120770473164800", "14474011161404511094734033074752742253413655751614356610567341121265043767296"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});
        // high part less, low part greater
        witness = await circuit.calculateWitness({
            in: ["7237005590812235547548506460376501784339189378421107463736385241046375727104", "14474011161404511094734033074752742253413655751614356610567341121265043767296"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});

        // high part equal, low part less
        witness = await circuit.calculateWitness({
            in: ["14474011161404511094734033074752742253413655751614356610567341121265043767296", "14474011168144497761521693023419496025168563420023642716202484241540946329600"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});
        // high part equal, low part equal
        witness = await circuit.calculateWitness({
            in: ["14474011161404511094734033074752742253413655751614356610567341121265043767296", "14474011161404511094734033074752742253413655751614356610567341121265043767296"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "0"});
        // high part equal, low part greater
        witness = await circuit.calculateWitness({
            in: ["14474011168144497761521693023419496025168563420023642716202484241540946329600", "14474011161404511094734033074752742253413655751614356610567341121265043767296"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});

        // high part greater, low part less
        witness = await circuit.calculateWitness({
            in: ["14474011161404511094734033074752742253413655751614356610567341121265043767296", "7237005590812235547548506460376501784339189378421107463736385241046375727104"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});
        // high part greater, low part equal
        witness = await circuit.calculateWitness({
            in: ["14474011161404511094734033074752742253413655751614356610567341121265043767296", "7237005584072248880760846511709748012584281710011821358101242120770473164800"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});
        // high part greater, low part greater
        witness = await circuit.calculateWitness({
            in: ["14474011168144497761521693023419496025168563420023642716202484241540946329600", "7237005584072248880760846511709748012584281710011821358101242120770473164800"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "1"});
    });

});
