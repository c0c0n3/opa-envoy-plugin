package oidc

import (
	"reflect"
	"testing"

	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	logt "github.com/open-policy-agent/opa/logging/test"

	"github.com/open-policy-agent/opa-envoy-plugin/envoyauth"
)

func buildTrigger() Trigger {
	cfg := &Config{
		CallbackUrl: "http://wada/wada",
		Realms: []*Realm{
			{
				Name:         "A",
				LoginURL:     "http://log/in/A",
				ClientID:     "id.A",
				ClientSecret: "s.A",
			},
			{
				Name:         "B",
				LoginURL:     "http://log/in/B",
				ClientID:     "id.B",
				ClientSecret: "s.B",
			},
		},
	}
	logger := logt.New()
	return NewTrigger(cfg, logger)
}

func countLogEntries(target Trigger) int {
	triggerImpl := target.(*authCodeFlow)
	logImpl := (triggerImpl.log).(*logt.Logger)
	return len(logImpl.Entries())
}

func emptyDeniedResponse() *ext_authz_v3.DeniedHttpResponse {
	return &ext_authz_v3.DeniedHttpResponse{}
}

var doNothingIfPolicyDidntOutputRealmFixtures = []*envoyauth.EvalResult{
	{Decision: false},
	{Decision: true},
	{Decision: map[string]interface{}{"allowed": false}},
	{Decision: map[string]interface{}{"allowed": true}},
}

func TestDoNothingIfPolicyDidntOutputRealm(t *testing.T) {
	for k, evalResult := range doNothingIfPolicyDidntOutputRealmFixtures {
		response := emptyDeniedResponse()
		trigger := buildTrigger()
		tweaked := trigger.Process(evalResult, response)

		if tweaked != nil {
			t.Errorf("[%d] want: nil; got: %v", k, tweaked)
		}
		if !reflect.DeepEqual(response, emptyDeniedResponse()) {
			t.Errorf("[%d] want: don't modify input response; got: %v",
				k, response)
		}
	}
}

func TestPolicyOutputsRealmNotInConfig(t *testing.T) {
	evalResult := &envoyauth.EvalResult{
		Decision: map[string]interface{}{
			"allowed": false,
			"realm":   "not-in-config",
		},
	}
	response := emptyDeniedResponse()
	trigger := buildTrigger()
	initialLogEntriesCount := countLogEntries(trigger)
	tweaked := trigger.Process(evalResult, response)

	if !reflect.DeepEqual(response, tweaked) {
		t.Errorf("want: don't modify input response; got: %v", response)
	}
	if cnt := countLogEntries(trigger); cnt != initialLogEntriesCount+1 {
		t.Errorf("want: %d; got: %d", initialLogEntriesCount+1, cnt)
	}
}

func TestPolicyOutputsRealmInConfig(t *testing.T) {
	evalResult := &envoyauth.EvalResult{
		Decision: map[string]interface{}{
			"allowed": false,
			"realm":   "A",
		},
	}

	initialHeader := &ext_core_v3.HeaderValueOption{
		Header: &ext_core_v3.HeaderValue{
			Key:   "x-header",
			Value: "x",
		},
	}
	response := emptyDeniedResponse()
	response.Status = &ext_type_v3.HttpStatus{
		Code: ext_type_v3.StatusCode(ext_type_v3.StatusCode_SeeOther),
	}
	response.Headers = append(response.Headers, initialHeader)

	trigger := buildTrigger()
	tweaked := trigger.Process(evalResult, response)

	if tweaked == nil {
		t.Fatalf("want: tweaked response; got: nil")
	}
	if tweaked.Status.Code != 303 {
		t.Errorf("want: 303 status code; got: %v", tweaked.Status)
	}
	if cnt := len(tweaked.Headers); cnt != 2 {
		t.Fatalf("want: add location header to existing one; got: %d", cnt)
	}
	if !reflect.DeepEqual(initialHeader, tweaked.Headers[0]) {
		t.Errorf("want: don't modify input header; got: %v", tweaked.Headers[0])
	}
	if tweaked.Headers[1].Header.Key != "Location" {
		t.Errorf("want: add location header; got: %v", tweaked.Headers[1])
	}
}
