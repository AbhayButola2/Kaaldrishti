// Package graph — BoltDB snapshot persistence for InMemoryGraphStore.
//
// Snapshot() serializes the entire in-memory graph to a BoltDB file.
// Load() restores it on warm restart.
//
// BoltDB justification: zero CGo dependency (unlike SQLite), single-file,
// embedded — no external process or network required.
//
// Bucket layout:
//   "nodes" bucket: nodeID → JSON(domain.Node)
//   "edges" bucket: edgeID → JSON(domain.Edge)
//
// NOTE: Snapshot() acquires a write lock on the in-memory store while
// iterating, then releases it before writing to disk. This means the
// snapshot is consistent with the in-memory state at the time of lock
// acquisition, even if new events arrive during the disk write.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/kaaladrishti/engine/internal/domain"
	"github.com/rs/zerolog/log"
)

var (
	bucketNodes = []byte("nodes")
	bucketEdges = []byte("edges")
)

// Snapshot persists the full in-memory graph to the BoltDB snapshot file.
// This is NOT a no-op. It satisfies the warm-restart durability requirement.
func (s *InMemoryGraphStore) Snapshot(ctx context.Context) error {
	// Take a consistent snapshot of the in-memory state under the read lock.
	s.mu.RLock()
	nodes := s.allNodesUnsafe()
	edges := s.allEdgesUnsafe()
	s.mu.RUnlock()

	log.Info().
		Int("nodes", len(nodes)).
		Int("edges", len(edges)).
		Str("path", s.snapshotPath).
		Msg("graph: snapshot starting")

	db, err := bolt.Open(s.snapshotPath, 0o600, &bolt.Options{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("graph: snapshot: open BoltDB %q: %w", s.snapshotPath, err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			log.Error().Err(cerr).Msg("graph: snapshot: close BoltDB")
		}
	}()

	err = db.Update(func(tx *bolt.Tx) error {
		// Recreate buckets (delete+create ensures stale data is cleared).
		if err := tx.DeleteBucket(bucketNodes); err != nil && err != bolt.ErrBucketNotFound {
			return fmt.Errorf("delete nodes bucket: %w", err)
		}
		if err := tx.DeleteBucket(bucketEdges); err != nil && err != bolt.ErrBucketNotFound {
			return fmt.Errorf("delete edges bucket: %w", err)
		}

		nb, err := tx.CreateBucket(bucketNodes)
		if err != nil {
			return fmt.Errorf("create nodes bucket: %w", err)
		}
		eb, err := tx.CreateBucket(bucketEdges)
		if err != nil {
			return fmt.Errorf("create edges bucket: %w", err)
		}

		for _, n := range nodes {
			data, err := json.Marshal(n)
			if err != nil {
				return fmt.Errorf("marshal node %q: %w", n.ID, err)
			}
			if err := nb.Put([]byte(n.ID), data); err != nil {
				return fmt.Errorf("put node %q: %w", n.ID, err)
			}
		}
		for _, e := range edges {
			data, err := json.Marshal(e)
			if err != nil {
				return fmt.Errorf("marshal edge %q: %w", e.ID, err)
			}
			if err := eb.Put([]byte(e.ID), data); err != nil {
				return fmt.Errorf("put edge %q: %w", e.ID, err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("graph: snapshot: bolt transaction: %w", err)
	}

	log.Info().
		Int("nodes", len(nodes)).
		Int("edges", len(edges)).
		Str("path", s.snapshotPath).
		Msg("graph: snapshot complete")
	return nil
}

// Load restores the graph from the last BoltDB snapshot.
// Called on warm restart before the ingestion loop starts.
// If no snapshot file exists, Load returns nil (empty graph is valid).
func (s *InMemoryGraphStore) Load(ctx context.Context) error {
	db, err := bolt.Open(s.snapshotPath, 0o600, &bolt.Options{
		Timeout:  5 * time.Second,
		ReadOnly: true,
	})
	if err != nil {
		// No snapshot file: this is a cold start, not an error.
		log.Info().Str("path", s.snapshotPath).Msg("graph: no snapshot found; starting with empty graph")
		return nil
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			log.Error().Err(cerr).Msg("graph: load: close BoltDB")
		}
	}()

	var nodes []*domain.Node
	var edges []*domain.Edge

	err = db.View(func(tx *bolt.Tx) error {
		nb := tx.Bucket(bucketNodes)
		if nb != nil {
			if err := nb.ForEach(func(k, v []byte) error {
				var n domain.Node
				if err := json.Unmarshal(v, &n); err != nil {
					return fmt.Errorf("unmarshal node %q: %w", string(k), err)
				}
				nodes = append(nodes, &n)
				return nil
			}); err != nil {
				return err
			}
		}

		eb := tx.Bucket(bucketEdges)
		if eb != nil {
			if err := eb.ForEach(func(k, v []byte) error {
				var e domain.Edge
				if err := json.Unmarshal(v, &e); err != nil {
					return fmt.Errorf("unmarshal edge %q: %w", string(k), err)
				}
				edges = append(edges, &e)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("graph: load: bolt view: %w", err)
	}

	// Populate in-memory store under write lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, n := range nodes {
		cp := *n
		s.nodes[n.ID] = &cp
	}
	for _, e := range edges {
		cp := *e
		s.edges[e.ID] = &cp
		if s.adjOut[e.SrcNodeID] == nil {
			s.adjOut[e.SrcNodeID] = make(map[string]struct{})
		}
		s.adjOut[e.SrcNodeID][e.ID] = struct{}{}
		if s.adjIn[e.DstNodeID] == nil {
			s.adjIn[e.DstNodeID] = make(map[string]struct{})
		}
		s.adjIn[e.DstNodeID][e.ID] = struct{}{}
	}

	log.Info().
		Int("nodes", len(nodes)).
		Int("edges", len(edges)).
		Str("path", s.snapshotPath).
		Msg("graph: snapshot loaded (warm restart)")
	return nil
}
