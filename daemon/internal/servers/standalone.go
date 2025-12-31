// Copyright 2020 Anapaya Systems
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

package servers

import (
	"context"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// StandaloneDaemon implements the daemon.Connector interface by directly
// delegating to a DaemonEngine. This allows in-process usage of daemon
// functionality without going through gRPC.
// Also collects metrics for all operations.
type StandaloneDaemon struct {
	Engine  *DaemonEngine
	Metrics StandaloneMetrics
}

// TODO: NewStandaloneDaemon

// LocalIA returns the local ISD-AS number.
func (s *StandaloneDaemon) LocalIA(ctx context.Context) (addr.IA, error) {
	start := time.Now()
	ia, err := s.Engine.LocalIA(ctx)
	s.Metrics.LocalIA.observe(err, time.Since(start))
	return ia, err
}

// PortRange returns the beginning and the end of the SCION/UDP endhost port range.
func (s *StandaloneDaemon) PortRange(ctx context.Context) (uint16, uint16, error) {
	start := time.Now()
	startPort, endPort, err := s.Engine.PortRange(ctx)
	s.Metrics.PortRange.observe(err, time.Since(start))
	return startPort, endPort, err
}

// Interfaces returns the map of interface identifiers to the underlay internal address.
func (s *StandaloneDaemon) Interfaces(ctx context.Context) (map[uint16]netip.AddrPort, error) {
	start := time.Now()
	result, err := s.Engine.Interfaces(ctx)
	s.Metrics.Interfaces.observe(err, time.Since(start))
	return result, err
}

// Paths requests from the daemon a set of end to end paths between the source and destination.
func (s *StandaloneDaemon) Paths(
	ctx context.Context,
	dst, src addr.IA,
	f daemon.PathReqFlags,
) ([]snet.Path, error) {
	start := time.Now()
	paths, err := s.Engine.Paths(ctx, dst, src, f)
	s.Metrics.Paths.observe(err, time.Since(start), prom.LabelDst, dst.ISD().String())
	return paths, err
}

// ASInfo requests information about an AS. The zero IA returns local AS info.
func (s *StandaloneDaemon) ASInfo(ctx context.Context, ia addr.IA) (daemon.ASInfo, error) {
	start := time.Now()
	asInfo, err := s.Engine.ASInfo(ctx, ia)
	s.Metrics.ASInfo.observe(err, time.Since(start))
	return asInfo, err
}

// SVCInfo requests information about addresses and ports of infrastructure services.
func (s *StandaloneDaemon) SVCInfo(
	ctx context.Context,
	_ []addr.SVC,
) (map[addr.SVC][]string, error) {
	start := time.Now()
	uris, err := s.Engine.SVCInfo(ctx)
	s.Metrics.SVCInfo.observe(err, time.Since(start))
	if err != nil {
		return nil, err
	}
	result := make(map[addr.SVC][]string)
	if len(uris) > 0 {
		result[addr.SvcCS] = uris
	}
	return result, nil
}

// RevNotification sends a RevocationInfo message to the daemon.
func (s *StandaloneDaemon) RevNotification(
	ctx context.Context,
	revInfo *path_mgmt.RevInfo,
) error {
	start := time.Now()
	err := s.Engine.NotifyInterfaceDown(ctx, revInfo.RawIsdas, uint64(revInfo.IfID))
	s.Metrics.InterfaceDown.observe(err, time.Since(start))
	return err
}

// DRKeyGetASHostKey requests an AS-Host Key from the daemon.
func (s *StandaloneDaemon) DRKeyGetASHostKey(
	ctx context.Context,
	meta drkey.ASHostMeta,
) (drkey.ASHostKey, error) {
	start := time.Now()
	key, err := s.Engine.DRKeyGetASHostKey(ctx, meta)
	s.Metrics.DRKeyASHost.observe(err, time.Since(start))
	return key, err
}

// DRKeyGetHostASKey requests a Host-AS Key from the daemon.
func (s *StandaloneDaemon) DRKeyGetHostASKey(
	ctx context.Context,
	meta drkey.HostASMeta,
) (drkey.HostASKey, error) {
	start := time.Now()
	key, err := s.Engine.DRKeyGetHostASKey(ctx, meta)
	s.Metrics.DRKeyHostAS.observe(err, time.Since(start))
	return key, err
}

// DRKeyGetHostHostKey requests a Host-Host Key from the daemon.
func (s *StandaloneDaemon) DRKeyGetHostHostKey(
	ctx context.Context,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {
	start := time.Now()
	key, err := s.Engine.DRKeyGetHostHostKey(ctx, meta)
	s.Metrics.DRKeyHostHost.observe(err, time.Since(start))
	return key, err
}

func (s *StandaloneDaemon) Close() error {
	return nil
}

// Compile-time assertion that StandaloneDaemon implements daemon.Connector.
var _ daemon.Connector = (*StandaloneDaemon)(nil)

// StandaloneMetrics contains metrics for all StandaloneDaemon operations.
type StandaloneMetrics struct {
	LocalIA       requestMetric
	PortRange     requestMetric
	Interfaces    requestMetric
	Paths         requestMetric
	ASInfo        requestMetric
	SVCInfo       requestMetric
	InterfaceDown requestMetric
	DRKeyASHost   requestMetric
	DRKeyHostAS   requestMetric
	DRKeyHostHost requestMetric
}

// requestMetric contains the metrics for a given request type.
type requestMetric struct {
	Requests metrics.Counter
	Latency  metrics.Histogram
}

func (m requestMetric) observe(err error, latency time.Duration, extraLabels ...string) {
	result := standaloneResultFromErr(err)
	if m.Requests != nil {
		m.Requests.With(append([]string{prom.LabelResult, result}, extraLabels...)...).Add(1)
	}
	if m.Latency != nil {
		m.Latency.With(prom.LabelResult, result).Observe(latency.Seconds())
	}
}

func standaloneResultFromErr(err error) string {
	if err == nil {
		return prom.Success
	}
	if serrors.IsTimeout(err) {
		return prom.ErrTimeout
	}
	return prom.ErrNotClassified
}

// NewStandaloneMetrics creates metrics for StandaloneDaemon operations.
func NewStandaloneMetrics() StandaloneMetrics {
	resultLabels := []string{prom.LabelResult}
	pathLabels := []string{prom.LabelResult, prom.LabelDst}
	return StandaloneMetrics{
		LocalIA:       newRequestMetric("local_ia", "local IA", resultLabels),
		PortRange:     newRequestMetric("port_range", "port range", resultLabels),
		Interfaces:    newRequestMetric("interfaces", "interfaces", resultLabels),
		Paths:         newRequestMetric("paths", "path", pathLabels),
		ASInfo:        newRequestMetric("as_info", "AS info", resultLabels),
		SVCInfo:       newRequestMetric("svc_info", "SVC info", resultLabels),
		InterfaceDown: newRequestMetric("interface_down", "interface down notification", resultLabels),
		DRKeyASHost:   newRequestMetric("drkey_as_host", "DRKey AS-Host", resultLabels),
		DRKeyHostAS:   newRequestMetric("drkey_host_as", "DRKey Host-AS", resultLabels),
		DRKeyHostHost: newRequestMetric("drkey_host_host", "DRKey Host-Host", resultLabels),
	}
}

func newRequestMetric(subsystem, description string, labels []string) requestMetric {
	return requestMetric{
		Requests: metrics.NewPromCounterFrom(
			prometheus.CounterOpts{
				Namespace: "standalone_daemon",
				Subsystem: subsystem,
				Name:      "requests_total",
				Help:      "The amount of " + description + " requests.",
			},
			labels,
		),
		Latency: metrics.NewPromHistogramFrom(
			prometheus.HistogramOpts{
				Namespace: "standalone_daemon",
				Subsystem: subsystem,
				Name:      "request_duration_seconds",
				Help:      "Time to handle " + description + " requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			},
			[]string{prom.LabelResult},
		),
	}
}
