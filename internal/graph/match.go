// SPDX-License-Identifier: Apache-2.0
package graph

import "strings"

// MatchPattern implements IAM-style wildcard matching: "*" matches any
// sequence, "?" matches exactly one character, everything else must
// match literally. Used for both AWS IAM (action/resource ARN patterns)
// and Kubernetes RBAC (resource name patterns, and the implicit "*"
// verb some ClusterRoles grant) -- one matcher, since both systems use
// the same glob semantics for this.
func MatchPattern(pattern, value string) bool {
	return matchHelper(pattern, value)
}

func matchHelper(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	// Fast path: no wildcards at all -- exact match.
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == value
	}
	return globMatch(pattern, value)
}

// globMatch is a small, dependency-free glob matcher (equivalent to
// path.Match but without path.Match's slash-boundary rules, which don't
// apply to ARNs or k8s resource names) -- classic DP over
// pattern/value, correct for the two wildcard characters IAM actually
// uses.
func globMatch(pattern, value string) bool {
	p, v := []rune(pattern), []rune(value)
	dp := make([][]bool, len(p)+1)
	for i := range dp {
		dp[i] = make([]bool, len(v)+1)
	}
	dp[0][0] = true
	for i := 1; i <= len(p); i++ {
		if p[i-1] == '*' {
			dp[i][0] = dp[i-1][0]
		}
	}
	for i := 1; i <= len(p); i++ {
		for j := 1; j <= len(v); j++ {
			switch p[i-1] {
			case '*':
				dp[i][j] = dp[i-1][j] || dp[i][j-1]
			case '?':
				dp[i][j] = dp[i-1][j-1]
			default:
				dp[i][j] = dp[i-1][j-1] && p[i-1] == v[j-1]
			}
		}
	}
	return dp[len(p)][len(v)]
}
