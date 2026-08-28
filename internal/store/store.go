// SPDX-License-Identifier: Apache-2.0
// Package store persists a graph.Graph to disk as JSON. Dependency-free
// and deliberately simple -- an MVP CLI tool re-ingesting on demand
// doesn't need a real database yet. Swapping this for Postgres (per the
// product plan's own stated lean-early option) or a graph database
// later only touches this package: Load/Save's signatures are the whole
// contract the CLI depends on.
package store

import (
	"encoding/json"
	"os"

	"github.com/becash143/authz-graph/internal/graph"
)

type serializedGraph struct {
	Nodes []graph.Node `json:"nodes"`
	Edges []graph.Edge `json:"edges"`
}

func Save(path string, g *graph.Graph) error {
	sg := serializedGraph{Edges: g.AllEdges()}
	for _, n := range g.Nodes {
		sg.Nodes = append(sg.Nodes, n)
	}
	data, err := json.MarshalIndent(sg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func Load(path string) (*graph.Graph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sg serializedGraph
	if err := json.Unmarshal(data, &sg); err != nil {
		return nil, err
	}
	g := graph.New()
	for _, n := range sg.Nodes {
		g.AddNode(n)
	}
	for _, e := range sg.Edges {
		if err := g.AddEdge(e); err != nil {
			return nil, err
		}
	}
	return g, nil
}
