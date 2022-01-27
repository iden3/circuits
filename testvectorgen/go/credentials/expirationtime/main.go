package main

import (
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"math"
	"math/big"
	"test/utils"
	"time"
)

func main() {

	fmt.Println("----------------------------------")
	fmt.Println("------- Claim with expiration time:")

	var schemaHash core.SchemaHash
	newInt := big.NewInt(25)
	copy(schemaHash[:], newInt.Bytes())

	claim, _ := core.NewClaim(
		schemaHash,
		core.WithRevocationNonce(math.MaxUint64),
		core.WithExpirationDate(time.Unix(1669800009, 0)),
	)

	date, _ := claim.GetExpirationDate()
	fmt.Println(date.Unix())

	utils.PrintClaim("claim", claim)
}
