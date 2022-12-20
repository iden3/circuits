package sybil

import "testing"

func TestHappyFlow(t *testing.T) {

	desc := "Sybil resistance - Happy flow test"

	generateTestData(t, desc, "happyflow")
}
