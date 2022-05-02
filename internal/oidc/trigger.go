package oidc

import (
	"fmt"
	"strings"

	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	pb "google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/open-policy-agent/opa-envoy-plugin/envoyauth"
	"github.com/open-policy-agent/opa/logging"
)

type Trigger interface {
	Process(
		result *envoyauth.EvalResult,
		response *ext_authz_v3.DeniedHttpResponse) *ext_authz_v3.DeniedHttpResponse
}

type authCodeFlow struct {
	cfg ConfigReader
	log logging.Logger
}

func NewTrigger(cfg *Config, log logging.Logger) Trigger {
	return &authCodeFlow{
		cfg: NewConfigReader(cfg),
		log: log,
	}
}

func (acf *authCodeFlow) Process(
	result *envoyauth.EvalResult,
	response *ext_authz_v3.DeniedHttpResponse) *ext_authz_v3.DeniedHttpResponse {
	trigger, realm := shouldTriggerAuthCodeFlow(result)
	if trigger {
		if err := acf.buildResponse(response, realm); err != nil {
			acf.log.WithFields(map[string]interface{}{
				"error":    err,
				"realm":    realm,
				"response": response,
			}).Error("Failed to trigger OIDC Authorization Code flow.")
		}
		return response // unchanged if buildResponse error
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

func (acf *authCodeFlow) buildResponse(response *ext_authz_v3.DeniedHttpResponse, realm string) error {
	redirectURL, err := acf.buildRedirectURL(realm)
	if err != nil {
		return err
	}

	location := redirectHeader(redirectURL)
	response.Headers = append(response.Headers, location)
	response.Status = redirectStatus()

	return nil
}

func redirectStatus() *ext_type_v3.HttpStatus {
	return &ext_type_v3.HttpStatus{
		Code: ext_type_v3.StatusCode(ext_type_v3.StatusCode_SeeOther),
	}
}

func redirectHeader(url string) *ext_core_v3.HeaderValueOption {
	return &ext_core_v3.HeaderValueOption{
		Header: &ext_core_v3.HeaderValue{
			Key:   "Location",
			Value: url,
		},
		Append: pb.Bool(false),
	}
}

func (acf *authCodeFlow) buildRedirectURL(realm string) (string, error) {
	if realmConfig := acf.cfg.LookupRealm(realm); realmConfig != nil {
		return realmConfig.LoginURL, nil // TODO
	}
	return "", RealmLookupError(realm)
}

func RealmLookupError(realm string) error {
	msg := "policy wants to redirect downstream client to realm login " +
		"but no realm login endpoint found in configuration for realm " +
		"name: '%s'"
	return fmt.Errorf(msg, realm)
}
