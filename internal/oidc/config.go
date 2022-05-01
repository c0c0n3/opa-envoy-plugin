package oidc

type ConfigReader interface {
	LookupRealm(name string) *Realm
	CallbackUrl() string
}

type Realm struct {
	Name         string `json:"name"`
	LoginUrl     string `json:"login-url"`
	ClientId     string `json:"client-id"`
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
	return nil // TODO
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
