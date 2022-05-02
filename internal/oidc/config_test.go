package oidc

import (
	"testing"
)

func TestNoOpConfigReader(t *testing.T) {
	target := NewConfigReader(nil)

	if target == nil {
		t.Fatalf("want: no op reader; got: nil")
	}

	if r := target.LookupRealm("name"); r != nil {
		t.Errorf("want: no realm; got: %s", r)
	}

	if url := target.CallbackUrl(); len(url) > 0 {
		t.Errorf("want: empty callback url; got: %s", url)
	}
}

func TestRealmLookup(t *testing.T) {
	cfg := &Config{
		Realms: []*Realm{
			{Name: "A"}, {Name: "B"},
		},
	}
	reader := NewConfigReader(cfg)

	if r := reader.LookupRealm("A"); r == nil {
		t.Errorf("want: realm A; got: nil")
	}
	if r := reader.LookupRealm("B"); r == nil {
		t.Errorf("want: realm B; got: nil")
	}
}

func TestAcceptNilConfig(t *testing.T) {
	if err := ValidateConfig(nil); err != nil {
		t.Errorf("want: nil config should be treated as empty; got: %v", err)
	}
}

var rejectInvalidCallbackURLFixtures = []string{
	"", "ftp://wada/wada", "/path/only", ":8080",
}

func TestRejectInvalidCallbackURL(t *testing.T) {
	for k, rawURL := range rejectInvalidCallbackURLFixtures {
		cfg := &Config{CallbackUrl: rawURL}
		if err := ValidateConfig(cfg); err == nil {
			t.Errorf("[%d] want: invalid callback URL; got: nil", k)
		}
	}
}

func TestAcceptEmptyRealms(t *testing.T) {
	cfg := &Config{CallbackUrl: "http://wada/wada"}
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("want: accept empty realms; got: %v", err)
	}
}

func TestRejectEmptyRealmName(t *testing.T) {
	cfg := &Config{
		CallbackUrl: "http://wada/wada",
		Realms: []*Realm{
			{
				Name:         " ",
				LoginURL:     "https://log/in",
				ClientID:     "id",
				ClientSecret: "s",
			},
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Errorf("want: reject empty realm name; got: nil")
	}
}

func TestRejectInvalidLoginURL(t *testing.T) {
	cfg := &Config{
		CallbackUrl: "http://wada/wada",
		Realms: []*Realm{
			{
				Name:         "A",
				LoginURL:     "log/in",
				ClientID:     "id",
				ClientSecret: "s",
			},
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Errorf("want: reject invalid login URL; got: nil")
	}
}

func TestRejectEmptyClientID(t *testing.T) {
	cfg := &Config{
		CallbackUrl: "https://wada/wada",
		Realms: []*Realm{
			{Name: "A", LoginURL: "http://log/in", ClientSecret: "s"},
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Errorf("want: reject empty client ID; got: nil")
	}
}

func TestRejectEmptyClientSecret(t *testing.T) {
	cfg := &Config{
		CallbackUrl: "http://wada/wada",
		Realms: []*Realm{
			{Name: "A", LoginURL: "https://log/in", ClientID: "id"},
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Errorf("want: reject empty client secret; got: nil")
	}
}
