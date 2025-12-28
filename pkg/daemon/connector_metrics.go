// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// ConnectorMetrics contains all metrics for daemon backend operations.
type ConnectorMetrics struct {
	PathsRequests              metrics.Counter
	PathsLatency               metrics.Histogram
	ASRequests                 metrics.Counter
	ASLatency                  metrics.Histogram
	InterfacesRequests         metrics.Counter
	InterfacesLatency          metrics.Histogram
	ServicesRequests           metrics.Counter
	ServicesLatency            metrics.Histogram
	InterfaceDownNotifications metrics.Counter
	InterfaceDownLatency       metrics.Histogram
}

// connectorMetricsWrapper wraps a Connector and records metrics.
type connectorMetricsWrapper struct {
	Connector
	Metrics ConnectorMetrics
}

// WrapWithMetrics wraps a Connector with metrics collection.
func WrapWithMetrics(connector Connector, namespace string) Connector {
	connectorMetrics := ConnectorMetrics{
		PathsRequests: metrics.NewPromCounterFrom(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "path",
				Name:      "requests_total",
				Help:      "The amount of path requests received.",
			}, []string{prom.LabelResult, prom.LabelDst},
		),
		PathsLatency: metrics.NewPromHistogramFrom(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "path",
				Name:      "request_duration_seconds",
				Help:      "Time to handle path requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, []string{prom.LabelResult},
		),
		ASRequests: metrics.NewPromCounterFrom(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "as_info",
				Name:      "requests_total",
				Help:      "The amount of AS requests received.",
			}, []string{prom.LabelResult},
		),
		ASLatency: metrics.NewPromHistogramFrom(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "as_info",
				Name:      "request_duration_seconds",
				Help:      "Time to handle AS requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, []string{prom.LabelResult},
		),
		InterfacesRequests: metrics.NewPromCounterFrom(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "if_info",
				Name:      "requests_total",
				Help:      "The amount of interfaces requests received.",
			}, []string{prom.LabelResult},
		),
		InterfacesLatency: metrics.NewPromHistogramFrom(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "if_info",
				Name:      "request_duration_seconds",
				Help:      "Time to handle interfaces requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, []string{prom.LabelResult},
		),
		ServicesRequests: metrics.NewPromCounterFrom(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "service_info",
				Name:      "requests_total",
				Help:      "The amount of services requests received.",
			}, []string{prom.LabelResult},
		),
		ServicesLatency: metrics.NewPromHistogramFrom(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "service_info",
				Name:      "request_duration_seconds",
				Help:      "Time to handle services requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, []string{prom.LabelResult},
		),
		InterfaceDownNotifications: metrics.NewPromCounter(
			prom.SafeRegister(
				prometheus.NewCounterVec(
					prometheus.CounterOpts{
						Namespace: namespace,
						Name:      "received_revocations_total",
						Help:      "The amount of revocations received.",
					}, []string{prom.LabelResult, prom.LabelSrc},
				),
			).(*prometheus.CounterVec),
		),
		InterfaceDownLatency: metrics.NewPromHistogramFrom(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "revocation",
				Name:      "notification_duration_seconds",
				Help:      "Time to handle interface down notifications.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, []string{prom.LabelResult},
		),
	}

	return &connectorMetricsWrapper{
		Connector: connector,
		Metrics:   connectorMetrics,
	}
}

// Note: No metrics are collected for LocalIA, PortRange and DRKey functions.

func (c *connectorMetricsWrapper) Interfaces(ctx context.Context) (
	map[uint16]netip.AddrPort, error,
) {
	start := time.Now()
	interfaces, err := c.Connector.Interfaces(ctx)
	result := errToResult(err)
	if c.Metrics.InterfacesRequests != nil {
		c.Metrics.InterfacesRequests.With(prom.LabelResult, result).Add(1)
	}
	if c.Metrics.InterfacesLatency != nil {
		c.Metrics.InterfacesLatency.With(
			prom.LabelResult, result,
		).Observe(time.Since(start).Seconds())
	}
	return interfaces, unwrapMetricsError(err)
}

func (c *connectorMetricsWrapper) Paths(
	ctx context.Context, dst, src addr.IA, f PathReqFlags,
) ([]snet.Path, error) {
	start := time.Now()
	paths, err := c.Connector.Paths(ctx, dst, src, f)
	result := errToResult(err)
	if c.Metrics.PathsRequests != nil {
		c.Metrics.PathsRequests.With(
			prom.LabelResult, result, prom.LabelDst, dst.ISD().String(),
		).Add(1)
	}
	if c.Metrics.PathsLatency != nil {
		c.Metrics.PathsLatency.With(prom.LabelResult, result).Observe(time.Since(start).Seconds())
	}
	return paths, unwrapMetricsError(err)
}

func (c *connectorMetricsWrapper) ASInfo(ctx context.Context, ia addr.IA) (ASInfo, error) {
	start := time.Now()
	info, err := c.Connector.ASInfo(ctx, ia)
	result := errToResult(err)
	if c.Metrics.ASRequests != nil {
		c.Metrics.ASRequests.With(prom.LabelResult, result).Add(1)
	}
	if c.Metrics.ASLatency != nil {
		c.Metrics.ASLatency.With(prom.LabelResult, result).Observe(time.Since(start).Seconds())
	}
	return info, unwrapMetricsError(err)
}

func (c *connectorMetricsWrapper) SVCInfo(
	ctx context.Context, svcTypes []addr.SVC,
) (map[addr.SVC][]string, error) {
	start := time.Now()
	info, err := c.Connector.SVCInfo(ctx, svcTypes)
	result := errToResult(err)
	if c.Metrics.ServicesRequests != nil {
		c.Metrics.ServicesRequests.With(prom.LabelResult, result).Add(1)
	}
	if c.Metrics.ServicesLatency != nil {
		c.Metrics.ServicesLatency.With(
			prom.LabelResult, result,
		).Observe(time.Since(start).Seconds())
	}
	return info, unwrapMetricsError(err)
}

func (c *connectorMetricsWrapper) RevNotification(
	ctx context.Context, revInfo *path_mgmt.RevInfo,
) error {
	start := time.Now()
	err := c.Connector.RevNotification(ctx, revInfo)
	result := errToResult(err)
	if c.Metrics.InterfaceDownNotifications != nil {
		c.Metrics.InterfaceDownNotifications.With(
			prom.LabelResult, result, prom.LabelSrc, "notification",
		).Add(1)
	}
	if c.Metrics.InterfaceDownLatency != nil {
		c.Metrics.InterfaceDownLatency.With(
			prom.LabelResult, result,
		).Observe(time.Since(start).Seconds())
	}
	return unwrapMetricsError(err)
}

type metricsError struct {
	err    error
	result string
}

func (e metricsError) Error() string {
	return e.err.Error()
}

func errToResult(err error) string {
	if err == nil {
		return prom.Success
	}
	if merr, ok := err.(metricsError); ok && merr.result != "" {
		if serrors.IsTimeout(merr.err) {
			return prom.ErrTimeout
		}
		return merr.result
	}
	if serrors.IsTimeout(err) {
		return prom.ErrTimeout
	}
	return prom.ErrNotClassified
}

func unwrapMetricsError(err error) error {
	if err == nil {
		return nil
	}
	if merr, ok := err.(metricsError); ok {
		return merr.err
	}
	return err
}
