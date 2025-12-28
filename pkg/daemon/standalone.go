// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/segment/segfetcher"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
	segverifier "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/storage"
	truststoragemetrics "github.com/scionproto/scion/private/storage/trust/metrics"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/compat"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

// StandaloneOption is a functional option for NewStandaloneService.
type StandaloneOption func(*standaloneOptions)

// DefaultConfigDir is the default configuration directory for SCION.
const DefaultConfigDir = "/etc/scion"

type standaloneOptions struct {
	configDir              string
	disableSegVerification bool
	enablePeriodicCleanup  bool
	enableMetrics          bool
}

// WithConfigDir sets the configuration directory for trust material.
// Defaults to /etc/scion.
func WithConfigDir(dir string) StandaloneOption {
	return func(o *standaloneOptions) {
		o.configDir = dir
	}
}

// WithDisableSegVerification disables segment verification.
// WARNING: This should NOT be used in production!
func WithDisableSegVerification() StandaloneOption {
	return func(o *standaloneOptions) {
		o.disableSegVerification = true
	}
}

// WithPeriodicCleanup enables periodic cleanup of path database and revocation cache.
func WithPeriodicCleanup() StandaloneOption {
	return func(o *standaloneOptions) {
		o.enablePeriodicCleanup = true
	}
}

// WithMetrics enables metrics collection for the standalone daemon.
func WithMetrics() StandaloneOption {
	return func(o *standaloneOptions) {
		o.enableMetrics = true
	}
}

// LoadTopologyFromFile loads a topology from a file and starts a background loader.
// The returned Topology can be passed to NewStandaloneService.
// The caller should ensure the context is cancelled when the topology is no longer needed.
func LoadTopologyFromFile(ctx context.Context, topoFile string) (Topology, error) {
	loader, err := topology.NewLoader(
		topology.LoaderCfg{
			File:      topoFile,
			Reload:    nil,
			Validator: &topology.DefaultValidator{},
			Metrics:   newLoaderMetrics(),
		},
	)
	if err != nil {
		return nil, serrors.Wrap("creating topology loader", err)
	}

	go func() {
		defer log.HandlePanic()
		_ = loader.Run(ctx)
	}()

	return loader, nil
}

// newLoaderMetrics creates metrics for the topology loader.
func newLoaderMetrics() topology.LoaderMetrics {
	updates := prom.NewCounterVec(
		"", "",
		"topology_updates_total",
		"The total number of updates.",
		[]string{prom.LabelResult},
	)
	return topology.LoaderMetrics{
		ValidationErrors: metrics.NewPromCounter(updates).With(prom.LabelResult, "err_validate"),
		ReadErrors:       metrics.NewPromCounter(updates).With(prom.LabelResult, "err_read"),
		LastUpdate: metrics.NewPromGauge(
			prom.NewGaugeVec(
				"", "",
				"topology_last_update_time",
				"Timestamp of the last successful update.",
				[]string{},
			),
		),
		Updates: metrics.NewPromCounter(updates).With(prom.LabelResult, prom.Success),
	}
}

// standaloneConnector wraps a Connector to track background tasks and storages.
type standaloneConnector struct {
	Connector

	pathDBCleaner *periodic.Runner
	pathDB        storage.PathDB
	revCache      revcache.RevCache
	rcCleaner     *periodic.Runner
	trustDB       storage.TrustDB
	trcLoaderTask *periodic.Runner
}

// NewStandaloneService creates a daemon Connector that runs locally without a daemon process.
// It requires a Topology (use LoadTopology to create one from a file) and accepts
// functional options for configuration.
//
// The returned Connector can be used directly by SCION applications instead of connecting
// to a daemon via gRPC.
//
// Example:
//
//	topo, err := daemon.LoadTopology(ctx, "/path/to/topology.json")
//	if err != nil { ... }
//	conn, err := daemon.NewStandaloneService(ctx, topo,
//	    daemon.WithConfigDir("/path/to/config"),
//	    daemon.WithMetrics(),
//	)
func NewStandaloneService(
	ctx context.Context, topo Topology, opts ...StandaloneOption,
) (Connector, error) {
	options := &standaloneOptions{
		configDir: DefaultConfigDir,
	}
	for _, opt := range opts {
		opt(options)
	}

	_, errCtx := errgroup.WithContext(ctx)

	// Create dialer for control service
	dialer := &grpc.TCPDialer{
		SvcResolver: func(dst addr.SVC) []resolver.Address {
			if base := dst.Base(); base != addr.SvcCS {
				panic(
					"unsupported address type, possible implementation error: " +
						base.String(),
				)
			}
			targets := []resolver.Address{}
			for _, entry := range topo.ControlServiceAddresses() {
				targets = append(targets, resolver.Address{Addr: entry.String()})
			}
			return targets
		},
	}

	// Create RPC requester for segment fetching
	var requester segfetcher.RPC = &segfetchergrpc.Requester{
		Dialer: dialer,
	}

	// Initialize in-memory path storage
	pathDB, err := storage.NewInMemoryPathStorage()
	if err != nil {
		return nil, serrors.Wrap("initializing path storage", err)
	}

	// Initialize revocation cache
	revCache := storage.NewRevocationStorage()

	// Start periodic cleaners if enabled
	var cleaner *periodic.Runner
	var rcCleaner *periodic.Runner
	if options.enablePeriodicCleanup {
		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		cleaner = periodic.Start(
			pathdb.NewCleaner(pathDB, "sd_segments"),
			300*time.Second, 295*time.Second,
		)

		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		rcCleaner = periodic.Start(
			revcache.NewCleaner(revCache, "sd_revocation"),
			10*time.Second, 10*time.Second,
		)
	}

	var trustDB storage.TrustDB
	var inspector trust.Inspector
	var verifier segverifier.Verifier
	var trcLoaderTask *periodic.Runner

	// Create trust engine unless verification is disabled
	if options.disableSegVerification {
		log.Info("SEGMENT VERIFICATION DISABLED -- SHOULD NOT USE IN PRODUCTION!")
		inspector = nil // avoids requiring trust material
		verifier = segverifier.AcceptAll{}
	} else {
		trustDB, err = storage.NewInMemoryTrustStorage()
		if err != nil {
			return nil, serrors.Wrap("initializing trust database", err)
		}
		trustDB = truststoragemetrics.WrapDB(
			trustDB, truststoragemetrics.Config{
				Driver: string(storage.BackendSqlite),
				QueriesTotal: metrics.NewPromCounterFrom(
					prometheus.CounterOpts{
						Name: "trustengine_db_queries_total",
						Help: "Total queries to the database",
					},
					[]string{"driver", "operation", prom.LabelResult},
				),
			},
		)
		engine, err := TrustEngine(
			errCtx, options.configDir, topo.IA(), trustDB, dialer,
		)
		if err != nil {
			return nil, serrors.Wrap("creating trust engine", err)
		}
		engine.Inspector = trust.CachingInspector{
			Inspector:          engine.Inspector,
			Cache:              cache.New(time.Minute, time.Minute),
			CacheHits:          metrics.NewPromCounter(trustmetrics.CacheHitsTotal),
			MaxCacheExpiration: time.Minute,
		}
		trcLoader := trust.TRCLoader{
			Dir: filepath.Join(options.configDir, "certs"),
			DB:  trustDB,
		}
		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		trcLoaderTask = periodic.Start(
			periodic.Func{
				Task: func(ctx context.Context) {
					res, err := trcLoader.Load(ctx)
					if err != nil {
						log.SafeInfo(log.FromCtx(ctx), "TRC loading failed", "err", err)
					}
					if len(res.Loaded) > 0 {
						log.SafeInfo(
							log.FromCtx(ctx),
							"Loaded TRCs from disk", "trcs", res.Loaded,
						)
					}
				},
				TaskName: "daemon_trc_loader",
			}, 10*time.Second, 10*time.Second,
		)

		verifier = compat.Verifier{
			Verifier: trust.Verifier{
				Engine:             engine,
				Cache:              cache.New(time.Minute, time.Minute),
				CacheHits:          metrics.NewPromCounter(trustmetrics.CacheHitsTotal),
				MaxCacheExpiration: time.Minute,
			},
		}
	}

	// Create fetcher
	newFetcher := fetcher.NewFetcher(
		fetcher.FetcherConfig{
			IA:            topo.IA(),
			MTU:           topo.MTU(),
			Core:          topo.Core(),
			NextHopper:    topo,
			RPC:           requester,
			PathDB:        pathDB,
			Inspector:     inspector,
			Verifier:      verifier,
			RevCache:      revCache,
			QueryInterval: 0,
		},
	)

	// Create and return the connector
	var connector Connector = &Daemon{
		IA:          topo.IA(),
		MTU:         topo.MTU(),
		Topology:    topo,
		Fetcher:     newFetcher,
		RevCache:    revCache,
		DRKeyClient: nil, // DRKey not supported in standalone daemon
	}

	if options.enableMetrics {
		connector = WrapWithMetrics(connector, "local_sd")
	}

	connectorWithClose := standaloneConnector{
		Connector:     connector,
		pathDBCleaner: cleaner,
		pathDB:        pathDB,
		revCache:      revCache,
		rcCleaner:     rcCleaner,
		trustDB:       trustDB,
		trcLoaderTask: trcLoaderTask,
	}

	return connectorWithClose, nil
}

func (s standaloneConnector) Close() error {
	err := s.Connector.Close()

	if s.pathDBCleaner != nil {
		s.pathDBCleaner.Stop()
	}
	if s.pathDB != nil {
		err1 := s.pathDB.Close()
		err = errors.Join(err, err1)
	}
	if s.revCache != nil {
		err1 := s.revCache.Close()
		err = errors.Join(err, err1)
	}
	if s.rcCleaner != nil {
		s.rcCleaner.Stop()
	}
	if s.trustDB != nil {
		err1 := s.trustDB.Close()
		err = errors.Join(err, err1)
	}
	if s.trcLoaderTask != nil {
		s.trcLoaderTask.Stop()
	}
	return err
}
