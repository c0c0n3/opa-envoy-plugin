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
