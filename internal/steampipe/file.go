// SPDX-License-Identifier: Apache-2.0
package steampipe

import "os"

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
