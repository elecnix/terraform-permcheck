// Package config reads the permcheck config file, permcheck.json.
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// Config is the permcheck config file schema (permcheck.json).
type Config struct {
	Exclude []iam.Exclusion `json:"exclude"`
	// StrictResources turns on --strict-resources. The flag, when given,
	// overrides it.
	StrictResources bool `json:"strict_resources,omitempty"`
	// Needs declares permissions a principal needs beyond what the terraform
	// resources imply. They are checked against the same policy.
	Needs []iam.Need `json:"needs,omitempty"`
	// AllowUnresolvedTypes turns on --allow-unresolved-types: a resource
	// type no schema source knows is reported but does not fail the run.
	// The flag, when given, overrides it.
	AllowUnresolvedTypes bool `json:"allow_unresolved_types,omitempty"`
}

// Load reads and validates the config file at filePath.
func Load(filePath string) (*Config, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return parse(raw)
}

// parse unmarshals and validates config JSON.
func parse(raw []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := iam.ValidateExclusions(c.Exclude); err != nil {
		return nil, err
	}
	if err := iam.ValidateNeeds(c.Needs); err != nil {
		return nil, err
	}
	return &c, nil
}
