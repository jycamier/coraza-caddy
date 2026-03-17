// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	corazaWAF "github.com/corazawaf/coraza/v3"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewMetricsRegistry(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	reg := newMetricsRegistry(registry)
	require.NotNil(t, reg)
	require.NotNil(t, reg.requestsTotal)
	require.NotNil(t, reg.requestsBlocked)
	require.NotNil(t, reg.rulesTriggered)
}

// newTestModuleWithMetrics creates a corazaModule with a real WAF and the given metrics.
func newTestModuleWithMetrics(t *testing.T, metrics *metricsRegistry, directives string) corazaModule {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	m := &corazaModule{Directives: directives}
	require.NoError(t, m.Provision(ctx))
	m.metrics = metrics
	return *m
}

// getCounterValue reads a counter value from a Prometheus registry.
func getCounterValue(t *testing.T, registry *prometheus.Registry, name string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() == name {
			var total float64
			for _, m := range f.GetMetric() {
				total += m.GetCounter().GetValue()
			}
			return total
		}
	}
	return 0
}

// getCounterWithLabels reads a counter value matching specific label values.
func getCounterWithLabels(t *testing.T, registry *prometheus.Registry, name string, labels prometheus.Labels) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() == name {
			for _, m := range f.GetMetric() {
				if matchLabels(m.GetLabel(), labels) {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func matchLabels(pairs []*io_prometheus.LabelPair, labels prometheus.Labels) bool {
	if len(pairs) != len(labels) {
		return false
	}
	for _, p := range pairs {
		v, ok := labels[p.GetName()]
		if !ok || v != p.GetValue() {
			return false
		}
	}
	return true
}

func TestRequestsTotalMetric(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	metrics := newMetricsRegistry(registry)

	m := newTestModuleWithMetrics(t, metrics, "SecRuleEngine On")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	rec := httptest.NewRecorder()

	err := m.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	require.NoError(t, err)

	found := getCounterValue(t, registry, "coraza_waf_requests_total")
	require.Equal(t, float64(1), found, "requestsTotal should be 1")
}

func TestProvisionInitializesMetrics(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	m := &corazaModule{Directives: "SecRuleEngine On"}
	require.NoError(t, m.Provision(ctx))
	require.NotNil(t, m.metrics)
	require.NotNil(t, m.metrics.requestsTotal)
	require.NotNil(t, m.metrics.requestsBlocked)
	require.NotNil(t, m.metrics.rulesTriggered)
}

func TestRequestsBlockedRequestPhase(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	metrics := newMetricsRegistry(registry)

	// Rule blocks GET /blocked at phase 1 (request headers)
	m := newTestModuleWithMetrics(t, metrics, `SecRuleEngine On
SecRule REQUEST_URI "/blocked" "id:1,phase:1,deny,status:403"`)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/blocked", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	rec := httptest.NewRecorder()

	err := m.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler should not be called")
		return nil
	}))
	require.Error(t, err)

	found := getCounterValue(t, registry, "coraza_waf_requests_blocked_total")
	require.Equal(t, float64(1), found, "requestsBlocked should be 1")
}

func TestRequestsBlockedResponsePhase(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	metrics := newMetricsRegistry(registry)

	// Rule blocks response containing "secret" at phase 4
	m := newTestModuleWithMetrics(t, metrics, `SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_BODY "secret" "id:2,phase:4,deny,status:403"`)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	rec := httptest.NewRecorder()

	_ = m.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("this is secret data"))
		return nil
	}))

	found := getCounterWithLabels(t, registry, "coraza_waf_requests_blocked_total", prometheus.Labels{
		"method": "GET",
		"action": "deny",
	})
	require.Equal(t, float64(1), found, "requestsBlocked should be 1 for response phase")
}

func TestRulesTriggeredMetric(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	metrics := newMetricsRegistry(registry)

	waf, err := corazaWAF.NewWAF(
		corazaWAF.NewWAFConfig().
			WithErrorCallback(newErrorCb(zap.NewNop(), metrics)).
			WithDirectives(`SecRuleEngine On
SecRule REQUEST_URI "/trigger" "id:1,phase:1,pass,log,severity:4"`),
	)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.ProcessURI("/trigger", "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	tx.Close()

	found := getCounterValue(t, registry, "coraza_waf_rules_triggered_total")
	require.Equal(t, float64(1), found, "rulesTriggered should be 1")
}
