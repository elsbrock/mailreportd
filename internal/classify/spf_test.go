package classify

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
)

// fakeResolver serves a fixed zone so tests never touch the network.
type fakeResolver struct {
	txt map[string][]string
	ip  map[string][]net.IP
	mx  map[string][]*net.MX

	txtCalls int
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.txtCalls++
	if records, ok := f.txt[name]; ok {
		return records, nil
	}
	return nil, fmt.Errorf("no such host: %s", name)
}

func (f *fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if addrs, ok := f.ip[host]; ok {
		return addrs, nil
	}
	return nil, fmt.Errorf("no such host: %s", host)
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if records, ok := f.mx[name]; ok {
		return records, nil
	}
	return nil, fmt.Errorf("no such host: %s", name)
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

func TestExpandIPMechanisms(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"example.org": {"v=spf1 ip4:203.0.113.0/24 ip6:2001:db8:98c0::/48 ip4:198.51.100.7 -all"},
	}}

	exp := New(r, 0, nil).Expand(context.Background(), "example.org")
	if exp.Err != nil {
		t.Fatalf("expand: %v", exp.Err)
	}
	if exp.All != "-" {
		t.Errorf("all qualifier = %q, want -", exp.All)
	}

	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"203.0.113.44", true},
		{"203.0.114.1", false},
		{"2001:db8:98c0::103", true},
		{"2a07::1", false},
		{"198.51.100.7", true},
		{"198.51.100.8", false},
	} {
		if got := exp.Authorizes(addr(t, tc.ip)); got != tc.want {
			t.Errorf("authorizes(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestExpandIncludeAndRedirect(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"example.org":         {"v=spf1 include:_spf.relay.example ip4:203.0.113.1 -all"},
		"_spf.relay.example":  {"v=spf1 ip4:192.0.2.0/24 redirect=_deep.relay.example"},
		"_deep.relay.example": {"v=spf1 ip4:198.51.100.0/24 -all"},
	}}

	exp := New(r, 0, nil).Expand(context.Background(), "example.org")
	if exp.Err != nil {
		t.Fatalf("expand: %v", exp.Err)
	}

	for _, ip := range []string{"203.0.113.1", "192.0.2.5", "198.51.100.9"} {
		if !exp.Authorizes(addr(t, ip)) {
			t.Errorf("expected %s to be authorized through the include chain", ip)
		}
	}
	if exp.Lookups != 2 {
		t.Errorf("lookups = %d, want 2 (one include, one redirect)", exp.Lookups)
	}
}

func TestExpandAAndMX(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{"example.org": {"v=spf1 a mx a:relay.example/24 -all"}},
		ip: map[string][]net.IP{
			"example.org":      {net.ParseIP("203.0.113.10")},
			"mail.example.org": {net.ParseIP("2001:db8:98c0::103")},
			"relay.example":    {net.ParseIP("192.0.2.77")},
		},
		mx: map[string][]*net.MX{
			"example.org": {{Host: "mail.example.org.", Pref: 10}},
		},
	}

	exp := New(r, 0, nil).Expand(context.Background(), "example.org")
	if exp.Err != nil {
		t.Fatalf("expand: %v", exp.Err)
	}

	if !exp.Authorizes(addr(t, "203.0.113.10")) {
		t.Error("bare a mechanism should authorize the domain's own address")
	}
	if !exp.Authorizes(addr(t, "2001:db8:98c0::103")) {
		t.Error("mx mechanism should authorize the mx host address")
	}
	// a:relay.example/24 widens 192.0.2.77 to 192.0.2.0/24.
	if !exp.Authorizes(addr(t, "192.0.2.1")) {
		t.Error("a mechanism with a cidr length should widen to the prefix")
	}
	if exp.Authorizes(addr(t, "192.0.3.1")) {
		t.Error("cidr widening should not escape the prefix")
	}
}

func TestNonPassQualifiersDoNotAuthorize(t *testing.T) {
	// A "-include" narrows the result at a receiver; crediting it would let a
	// spoofer be classified as one of ours.
	r := &fakeResolver{txt: map[string][]string{
		"example.org": {"v=spf1 -ip4:203.0.113.0/24 ~ip4:192.0.2.0/24 ?a:x.example +ip4:198.51.100.0/24 -all"},
		"x.example":   {"v=spf1 -all"},
	}}

	exp := New(r, 0, nil).Expand(context.Background(), "example.org")
	if exp.Err != nil {
		t.Fatalf("expand: %v", exp.Err)
	}

	if exp.Authorizes(addr(t, "203.0.113.1")) {
		t.Error("- qualified mechanism must not authorize")
	}
	if exp.Authorizes(addr(t, "192.0.2.1")) {
		t.Error("~ qualified mechanism must not authorize")
	}
	if !exp.Authorizes(addr(t, "198.51.100.1")) {
		t.Error("+ qualified mechanism must authorize")
	}
}

func TestLookupLimitIsEnforced(t *testing.T) {
	// Eleven includes: over the RFC 7208 limit, which is a real permerror at
	// receivers and therefore worth reporting rather than silently expanding.
	txt := map[string][]string{}
	record := "v=spf1"
	for i := 0; i < 11; i++ {
		name := fmt.Sprintf("inc%d.example", i)
		record += " include:" + name
		txt[name] = []string{fmt.Sprintf("v=spf1 ip4:192.0.2.%d -all", i+1)}
	}
	txt["example.org"] = []string{record + " -all"}

	exp := New(&fakeResolver{txt: txt}, 0, nil).Expand(context.Background(), "example.org")
	if !exp.Exceeded {
		t.Errorf("expected the lookup limit to be exceeded, got %d lookups", exp.Lookups)
	}
}

func TestIncludeLoopTerminates(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"a.example": {"v=spf1 include:b.example -all"},
		"b.example": {"v=spf1 include:a.example ip4:203.0.113.1 -all"},
	}}

	exp := New(r, 0, nil).Expand(context.Background(), "a.example")
	if exp.Err != nil {
		t.Fatalf("expand: %v", exp.Err)
	}
	if !exp.Authorizes(addr(t, "203.0.113.1")) {
		t.Error("loop guard should not lose the reachable mechanisms")
	}
}

func TestClassify(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"example.org": {"v=spf1 ip4:203.0.113.0/24 -all"},
	}}
	c := New(r, 0, nil)
	ctx := context.Background()

	tests := []struct {
		name                    string
		ip                      string
		dkimAligned, spfAligned bool
		want                    Class
	}{
		{"authorized source", "203.0.113.44", true, true, ClassSelf},
		{"authorized but failing", "203.0.113.44", false, false, ClassSelf},
		{"forwarded: dkim survives, spf breaks", "198.51.100.1", true, false, ClassForwarder},
		{"unauthorized and unsigned", "198.51.100.1", false, false, ClassUnknown},
		{"unauthorized, both pass", "198.51.100.1", true, true, ClassUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.Classify(ctx, "example.org", addr(t, tt.ip), tt.dkimAligned, tt.spfAligned)
			if got != tt.want {
				t.Errorf("class = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClassifyOverride(t *testing.T) {
	// An operator override covers sources that legitimately cannot appear in
	// SPF, such as a relay that signs with DKIM only.
	r := &fakeResolver{txt: map[string][]string{"example.org": {"v=spf1 -all"}}}
	override := netip.MustParsePrefix("198.51.100.0/24")

	c := New(r, 0, []netip.Prefix{override})
	if got := c.Classify(context.Background(), "example.org", addr(t, "198.51.100.5"), false, false); got != ClassSelf {
		t.Errorf("class = %q, want %q", got, ClassSelf)
	}
}

func TestExpansionIsCached(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{"example.org": {"v=spf1 ip4:203.0.113.0/24 -all"}}}
	c := New(r, 0, nil)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		c.Expand(ctx, "example.org")
	}
	if r.txtCalls != 1 {
		t.Errorf("txt lookups = %d, want 1 (cached)", r.txtCalls)
	}
}

func TestResolutionFailureIsCached(t *testing.T) {
	// Retrying a broken record on every scrape turns a DNS fault into a scrape
	// timeout, so failures are cached like any other result.
	r := &fakeResolver{txt: map[string][]string{}}
	c := New(r, 0, nil)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if exp := c.Expand(ctx, "missing.example"); exp.Err == nil {
			t.Fatal("expected a resolution error")
		}
	}
	if r.txtCalls != 1 {
		t.Errorf("txt lookups = %d, want 1 (failure cached)", r.txtCalls)
	}
}

func TestExpandNormalizesDomain(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{"example.org": {"v=spf1 ip4:203.0.113.0/24 -all"}}}
	c := New(r, 0, nil)
	ctx := context.Background()

	c.Expand(ctx, "EXAMPLE.ORG.")
	c.Expand(ctx, "example.org")
	if r.txtCalls != 1 {
		t.Errorf("txt lookups = %d, want 1: case and trailing dot must not split the cache", r.txtCalls)
	}
}
