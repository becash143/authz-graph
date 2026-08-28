// SPDX-License-Identifier: Apache-2.0
package ingest

import "encoding/json"

// StringOrSlice absorbs a genuinely real IAM inconsistency: a policy
// statement's Action/Resource field is valid JSON as either a single
// string ("s3:GetObject") or an array of strings (["s3:GetObject",
// "s3:ListBucket"]) -- and different tools normalize this differently.
// This decodes either shape into a []string so the rest of the
// ingester never has to care which form a given statement used.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*s = multi
	return nil
}
