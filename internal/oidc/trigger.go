package oidc

import (
	"strings"

	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	pb "google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/open-policy-agent/opa-envoy-plugin/envoyauth"
)

type Trigger interface {
	Process() *ext_authz_v3.DeniedHttpResponse
}

type authCodeFlow struct {
	configFilePath string
	result         *envoyauth.EvalResult
	response       *ext_authz_v3.DeniedHttpResponse
}

func NewTrigger(configFilePath string, result *envoyauth.EvalResult,
	response *ext_authz_v3.DeniedHttpResponse) Trigger {
	return &authCodeFlow{
		configFilePath: configFilePath,
		result:         result,
		response:       response,
	}
}

func (acf *authCodeFlow) Process() *ext_authz_v3.DeniedHttpResponse {
	trigger, realm := shouldTriggerAuthCodeFlow(acf.result)
	if trigger {
		response := acf.response
		location := redirectHeader(realm, acf.configFilePath)

		response.Headers = append(response.Headers, location)
		response.Status = redirectStatus()

		return response
	}
	return nil
}

func shouldTriggerAuthCodeFlow(result *envoyauth.EvalResult) (trigger bool, realm string) {
	realm = extractRealm(result)
	return len(realm) > 0, realm
}

func extractRealm(result *envoyauth.EvalResult) string {
	switch decision := result.Decision.(type) {
	case map[string]interface{}:
		if val, ok := decision["realm"]; ok {
			var strVal string
			if strVal, ok = val.(string); ok {
				return strings.TrimSpace(strVal)
			}
		}
	}
	return ""
}

func redirectStatus() *ext_type_v3.HttpStatus {
	return &ext_type_v3.HttpStatus{
		Code: ext_type_v3.StatusCode(ext_type_v3.StatusCode_SeeOther),
	}
}

// TODO move to struct to get rid of cfgFilePath param
func redirectHeader(realm string, cfgFilePath string) *ext_core_v3.HeaderValueOption {
	return &ext_core_v3.HeaderValueOption{
		Header: &ext_core_v3.HeaderValue{
			Key:   "Location",
			Value: buildRedirectUrl(realm, cfgFilePath),
		},
		Append: pb.Bool(false),
	}
}

func buildRedirectUrl(realm string, cfgFilePath string) string {
	return "https://google.com/" // TODO
}
