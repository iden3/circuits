package utils

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	core "github.com/iden3/go-iden3-core"
	jsonldSuite "github.com/iden3/go-schema-processor/json-ld"
	"github.com/iden3/go-schema-processor/loaders"

	"github.com/iden3/go-schema-processor/processor"
	"net/url"
)

const JSONLD SchemaFormat = "json-ld"

type SchemaFormat string

type Builder struct {
	ipfsUrl string
}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) Process(url, _type string, data []byte) (*processor.ParsedSlots, string, error) {
	schemaBytes, _, err := b.load(url)
	if err != nil {
		return nil, "", err
	}

	slots, err := b.getParsedSlots(url, _type, data)
	if err != nil {
		return nil, "", err
	}

	encodedSchema := b.createSchemaHash(schemaBytes, _type)

	return &slots, encodedSchema, nil
}

func (b *Builder) getLoader(_url string) (processor.SchemaLoader, error) {
	schemaURL, err := url.Parse(_url)
	if err != nil {
		return nil, err
	}
	switch schemaURL.Scheme {
	case "http", "https":
		return &loaders.HTTP{URL: _url}, nil
	case "ipfs":
		return loaders.IPFS{
			URL: b.ipfsUrl,
			CID: schemaURL.Host,
		}, nil
	default:
		return nil, fmt.Errorf("loader for %s is not supported", schemaURL.Scheme)
	}
}

func (b *Builder) getParsedSlots(schemaURL, credentialType string, dataBytes []byte) (processor.ParsedSlots, error) {
	ctx := context.Background()
	loader, err := b.getLoader(schemaURL)
	if err != nil {
		return processor.ParsedSlots{}, err
	}
	var parser processor.Parser
	var validator processor.Validator
	pr := &processor.Processor{}

	// for the case of schemaFormat := "json-ld"
	validator = jsonldSuite.Validator{Type:credentialType}
	parser = jsonldSuite.Parser{ClaimType: credentialType, ParsingStrategy: processor.OneFieldPerSlotStrategy}
	// TODO to remove

	// TODO : it's better to use specific processor (e.g. jsonProcessor.New()), but in this case it's a better option
	pr = processor.InitProcessorOptions(pr, processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))

	schema, _, err := pr.Load(ctx)
	if err != nil {
		return processor.ParsedSlots{}, err
	}
	err = pr.ValidateData(dataBytes, schema)
	if err != nil {
		return processor.ParsedSlots{}, err
	}
	return pr.ParseSlots(dataBytes, schema)
}

func (b *Builder) load(schemaURL string) (schema []byte, extension string, err error) {
	loader, err := b.getLoader(schemaURL)
	if err != nil {
		return nil, "", err
	}

	var schemaBytes []byte
	schemaBytes, _, err = loader.Load(context.Background())
	if err != nil {
		return nil, "", err
	}

	return schemaBytes, string(JSONLD), nil
}

func (b *Builder) createSchemaHash(schemaBytes []byte, credentialType string) string {
	var sHash core.SchemaHash
	h := crypto.Keccak256(schemaBytes, []byte(credentialType))
	copy(sHash[:], h[len(h)-16:])
	return hex.EncodeToString(sHash[:])
}
