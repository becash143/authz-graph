// SPDX-License-Identifier: Apache-2.0
// Package steampipe wraps the `steampipe` CLI as a subprocess -- this is
// the ingestion layer's entire connection to AWS/Kubernetes: no cloud
// SDKs, no Kubernetes client libraries, just `steampipe query <sql>
// --output json`. Every ingester in internal/ingest depends only on
// this Client, so swapping
// how a query actually executes (a persistent `steampipe service` +
// direct Postgres wire protocol, instead of one-off subprocess calls) is
// confined to this one file later, if ingestion volume ever makes that
// worth doing.
package steampipe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

type Client struct {
	// Binary is the path to the steampipe executable. Tests point this
	// at a fake stand-in script (see testdata/) instead of a real
	// steampipe install.
	Binary string
}

func New() *Client {
	return &Client{Binary: "steampipe"}
}

// queryOutput mirrors the real envelope `steampipe query ... --output
// json` actually emits: {"columns": [...], "rows": [...]}, not a bare
// array of row objects. Confirmed against real `steampipe query`
// output (a live Kubernetes plugin query) -- the fake test fixture
// originally used a bare array, which meant the ingest package's tests
// were passing against a mock shape that didn't match reality. Fixed
// here and in testdata/fake_steampipe.sh together; see the git history
// on this file for the lesson if this envelope shape ever needs
// revisiting.
type queryOutput struct {
	Columns []struct {
		Name     string `json:"name"`
		DataType string `json:"data_type"`
	} `json:"columns"`
	Rows json.RawMessage `json:"rows"`
}

// Query runs sql via `steampipe query <sql> --output json` and decodes
// the result's "rows" array into out (a pointer to a slice of
// structs/maps, matching encoding/json's normal unmarshal target
// shape).
func (c *Client) Query(sql string, out interface{}) error {
	cmd := exec.Command(c.Binary, "query", sql, "--output", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("steampipe query failed: %w (stderr: %s)", err, stderr.String())
	}

	var envelope queryOutput
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		return fmt.Errorf("decoding steampipe JSON envelope: %w (raw output: %s)", err, truncate(stdout.String(), 500))
	}
	if envelope.Rows == nil {
		return fmt.Errorf("steampipe output had no \"rows\" field -- got: %s", truncate(stdout.String(), 500))
	}
	if err := json.Unmarshal(envelope.Rows, out); err != nil {
		return fmt.Errorf("decoding steampipe rows into %T: %w (raw rows: %s)", out, err, truncate(string(envelope.Rows), 500))
	}
	return nil
}

// QueryFile reads sql from a file (keeps the actual SQL reviewable and
// versionable outside Go source) and runs it via Query.
func (c *Client) QueryFile(path string, out interface{}) error {
	sql, err := readFile(path)
	if err != nil {
		return fmt.Errorf("reading query file %s: %w", path, err)
	}
	return c.Query(sql, out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
