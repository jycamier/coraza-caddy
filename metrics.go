// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// metricsRegistry holds Prometheus instruments for WAF observability.
// All counters are safe for concurrent use.
type metricsRegistry struct {
	requestsTotal   *prometheus.CounterVec
	requestsBlocked *prometheus.CounterVec
	rulesTriggered  *prometheus.CounterVec
}

func newMetricsRegistry(registry *prometheus.Registry) *metricsRegistry {
	const ns, sub = "coraza", "waf"
	factory := promauto.With(registry)

	return &metricsRegistry{
		requestsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "requests_total",
			Help:      "Total requests processed by Coraza WAF.",
		}, []string{"method", "host"}),

		requestsBlocked: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "requests_blocked_total",
			Help:      "Requests blocked by Coraza WAF.",
		}, []string{"method", "action"}),

		rulesTriggered: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "rules_triggered_total",
			Help:      "WAF rules triggered.",
		}, []string{"severity"}),
	}
}
