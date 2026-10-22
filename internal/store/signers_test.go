package store

import (
	"context"
	"testing"
	"time"
)

// find returns the signer with the given domain and selector, or fails.
func find(t *testing.T, in []SignerDetail, domain, selector string) SignerDetail {
	t.Helper()
	for _, s := range in {
		if s.SigningDomain == domain && s.Selector == selector {
			return s
		}
	}
	t.Fatalf("no signer %s/%s in %+v", domain, selector, in)
	return SignerDetail{}
}

func TestSignersSeparatesValidFromAligned(t *testing.T) {
	s := testStore(t)
	ingest(t, s, relayedAggregateMessage(t))

	signers, omitted, err := s.Signers(context.Background(), time.Time{}, "", "", 100)
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	if len(signers) != 3 {
		t.Fatalf("got %d signers, want 3: %+v", len(signers), signers)
	}
	if omitted.Signers != 0 || omitted.Messages != 0 {
		t.Errorf("omitted = %+v, want zero", omitted)
	}

	// Busiest first: the relay signed 7 + 2 messages, ours 7, the subdomain 4.
	if signers[0].SigningDomain != "relay-smtp.net" {
		t.Errorf("first signer = %q, want relay-smtp.net", signers[0].SigningDomain)
	}

	// The whole point of the endpoint. The relay's signature verified on 7 of
	// the 9 messages it appeared on, yet it is foreign to the policy domain, so
	// none of that validity is what earned the receiver's dkim=pass.
	relay := find(t, signers, "relay-smtp.net", "rly2024-1")
	if relay.Relationship != RelationForeign {
		t.Errorf("relay relationship = %q, want %q", relay.Relationship, RelationForeign)
	}
	if relay.Messages != 9 {
		t.Errorf("relay messages = %d, want 9", relay.Messages)
	}
	if relay.SignaturePass != 7 {
		t.Errorf("relay signature_pass = %d, want 7", relay.SignaturePass)
	}

	// Ours is exact, and is what the receiver actually scored.
	ours := find(t, signers, "example.org", "selector1")
	if ours.Relationship != RelationExact {
		t.Errorf("our relationship = %q, want %q", ours.Relationship, RelationExact)
	}
	if ours.Messages != 7 || ours.SignaturePass != 7 || ours.EvaluatedPass != 7 {
		t.Errorf("ours = %+v, want 7/7/7", ours)
	}

	sub := find(t, signers, "news.example.org", "mktg")
	if sub.Relationship != RelationSubdomain {
		t.Errorf("subdomain relationship = %q, want %q", sub.Relationship, RelationSubdomain)
	}
	if sub.Messages != 4 {
		t.Errorf("subdomain messages = %d, want 4", sub.Messages)
	}
}

func TestSignersReportsTheRemainderItCutOff(t *testing.T) {
	s := testStore(t)
	ingest(t, s, relayedAggregateMessage(t))

	signers, omitted, err := s.Signers(context.Background(), time.Time{}, "", "", 1)
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("got %d signers, want 1", len(signers))
	}
	// A truncated answer has to say so, or it reads as "these are all of them".
	if omitted.Signers != 2 {
		t.Errorf("omitted signers = %d, want 2", omitted.Signers)
	}
	if omitted.Messages != 11 {
		t.Errorf("omitted messages = %d, want 11 (7 + 4)", omitted.Messages)
	}
}

func TestSignersFiltersByDomain(t *testing.T) {
	s := testStore(t)
	ingest(t, s, relayedAggregateMessage(t))

	signers, _, err := s.Signers(context.Background(), time.Time{}, "example.net", "", 100)
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	if len(signers) != 0 {
		t.Errorf("got %d signers for an unrelated domain, want 0", len(signers))
	}
}

func TestRelationship(t *testing.T) {
	cases := []struct {
		signing, policy, want string
	}{
		{"example.org", "example.org", RelationExact},
		{"EXAMPLE.ORG", "example.org", RelationExact},
		{"example.org.", "example.org", RelationExact},
		{"news.example.org", "example.org", RelationSubdomain},
		{"example.org", "news.example.org", RelationSubdomain},
		{"a.b.example.org", "example.org", RelationSubdomain},
		{"relay-smtp.net", "example.org", RelationForeign},
		// The suffix trap: a shared tail is not a subdomain relationship.
		{"notexample.org", "example.org", RelationForeign},
		{"", "example.org", RelationForeign},
		{"example.org", "", RelationForeign},
		// Known and accepted limit: siblings under one organizational domain
		// are relaxed-aligned, and a suffix rule cannot see it. This is why the
		// field is called relationship and the receiver's verdict is reported
		// alongside it.
		{"a.example.org", "b.example.org", RelationForeign},
	}
	for _, c := range cases {
		if got := Relationship(c.signing, c.policy); got != c.want {
			t.Errorf("Relationship(%q, %q) = %q, want %q", c.signing, c.policy, got, c.want)
		}
	}
}
