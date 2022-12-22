package sybil

import "testing"

func TestHappyFlowMTP(t *testing.T) {

	desc := "Sybil resistance - Happy flow test"

	generateTestDataMTP(t, desc, "happyflow - MTP")
}

func TestHappyFlowSig(t *testing.T) {

	desc := "Sybil resistance - Happy flow test"

	generateTestDataSig(t, desc, "happyflow - Sig")
}
