package oidc

import (
	"fmt"
	"net/url"
	"strings"
)

type ConfigReader interface {
	LookupRealm(name string) *Realm
	CallbackUrl() string
}

type Realm struct {
	Name         string `json:"name"`
	LoginURL     string `json:"login-url"`
	ClientID     string `json:"client-id"`
	ClientSecret string `json:"client-secret"`
}

type Config struct {
	CallbackUrl string   `json:"callback-url"`
	Realms      []*Realm `json:"realms"`
}

type cfgReader struct {
	cfg *Config
}

func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if err := validateAbsURL(cfg.CallbackUrl); err != nil {
		return fmt.Errorf("invalid callback URL: %v", err)
	}
	for k, realm := range cfg.Realms {
		if err := validateNonEmptyString(realm.Name); err != nil {
			return fmt.Errorf("invlaid realm[%d] name: %v", k, err)
		}
		if err := validateNonEmptyString(realm.ClientID); err != nil {
			return fmt.Errorf("invlaid realm[%d] client ID: %v", k, err)
		}
		if err := validateNonEmptyString(realm.ClientSecret); err != nil {
			return fmt.Errorf("invlaid realm[%d] client secret: %v", k, err)
		}
		if err := validateAbsURL(realm.LoginURL); err != nil {
			return fmt.Errorf("invlaid realm[%d] login URL: %v", k, err)
		}
	}
	return nil

	// TODO ideally we should accumulate validation errors instead of bailing
	// out on the first one we find...
}

func validateAbsURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("can't parse URL: '%s'; error: %v", rawURL, err)
	}
	if !parsed.IsAbs() {
		return fmt.Errorf("not an absolute URL: '%s'", rawURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("not an HTTP URL: '%s'", rawURL)
	}
	return nil
}

func validateNonEmptyString(target string) error {
	if trimmed := strings.TrimSpace(target); len(trimmed) == 0 {
		return fmt.Errorf("empty value")
	}
	return nil
}

func NewConfigReader(cfg *Config) ConfigReader {
	if cfg != nil {
		return &cfgReader{cfg: cfg}
	}
	return &cfgReader{cfg: &Config{}}
}

func (r *cfgReader) LookupRealm(name string) *Realm {
	for _, realm := range r.cfg.Realms {
		if realm.Name == name {
			return realm
		}
	}
	return nil
}

func (r *cfgReader) CallbackUrl() string {
	return r.cfg.CallbackUrl
}
