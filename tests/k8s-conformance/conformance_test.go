// Official Kubernetes SIG-Network Gateway API conformance test runner for Shunt (RFC 0028).
//
// Example invocation (against any cluster with Gateway API CRDs + Shunt deployed):
//
//	go test -v -timeout 20m ./... \
//	  --gateway-class=shunt \
//	  --conformance-profiles=GATEWAY-HTTP \
//	  --organization=shunt \
//	  --project=shunt \
//	  --url=https://github.com/shettyh/shunt \
//	  --version=0.3.0 \
//	  --contact=https://github.com/shettyh/shunt/issues \
//	  --report-output=conformance-report.yaml
package conformance_test

import (
	"testing"

	"sigs.k8s.io/gateway-api/conformance"
)

func TestGatewayAPIConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)
	if opts.GatewayClassName == "" {
		opts.GatewayClassName = "shunt"
	}
	conformance.RunConformanceWithOptions(t, opts)
}
