// Package classify decides whether a reported source address is one of ours.
//
// The authoritative answer is already published in DNS: a domain's SPF record
// is exactly the operator's own statement of which hosts may send for it. Using
// it means the daemon needs no knowledge of the MTA, the relay, or the hosting
// provider, and it stays correct when any of those change. A hardcoded list of
// relay netblocks would be correct for one deployment until the day the
// provider renumbers.
package classify

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Class is the bucket a source address falls into. It is deliberately a small
// closed set: it becomes a Prometheus label, and the source address itself
// never can.
type Class string

const (
	// ClassSelf is an address authorized by the domain's own SPF record, or by
	// an operator override.
	ClassSelf Class = "self"
	// ClassForwarder is an unauthorized address whose mail still carries an
	// aligned DKIM signature. That is the signature of forwarding: SPF breaks
	// across a hop, DKIM survives it.
	ClassForwarder Class = "forwarder"
	// ClassUnknown is everything else, which is what actually needs attention.
	ClassUnknown Class = "unknown"
)

// maxLookups is the RFC 7208 §4.6.4 limit on DNS-querying mechanisms. Records
// that exceed it produce a permerror at real receivers, so the limit is not
// merely advisory: it is a live deliverability fault worth surfacing.
const maxLookups = 10

// Resolver is the subset of *net.Resolver the expansion needs. It is an
// interface so tests do not touch the network.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// Expansion is the resolved contents of a domain's SPF record.
type Expansion struct {
	Domain string
	// Prefixes are the networks authorized by pass-qualified mechanisms.
	Prefixes []netip.Prefix
	// Lookups is how many DNS-querying mechanisms were consumed.
	Lookups int
	// Exceeded reports that the record needs more than ten lookups, which
	// makes it fail at receivers regardless of its contents.
	Exceeded bool
	// All is the qualifier on the terminal "all" mechanism: "-", "~", "?" or
	// "+". An empty value means the record has no all mechanism.
	All string
	// Err is set when the record could not be resolved at all.
	Err error
}

// Authorizes reports whether addr falls inside the expansion.
func (e *Expansion) Authorizes(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range e.Prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Classifier resolves and caches SPF expansions.
type Classifier struct {
	resolver  Resolver
	ttl       time.Duration
	overrides []netip.Prefix

	mu    sync.Mutex
	cache map[string]*cached
}

type cached struct {
	exp     *Expansion
	expires time.Time
}

// New returns a classifier. A zero ttl defaults to fifteen minutes, which is
// short enough to pick up an SPF change within an export cycle or two and long
// enough that a scrape does not become a DNS storm.
func New(resolver Resolver, ttl time.Duration, overrides []netip.Prefix) *Classifier {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Classifier{
		resolver:  resolver,
		ttl:       ttl,
		overrides: overrides,
		cache:     make(map[string]*cached),
	}
}

// Expand returns the cached expansion for a domain, resolving it if needed.
//
// A resolution failure is cached like any other result. Retrying a broken or
// slow record on every scrape turns a DNS problem into a scrape timeout.
func (c *Classifier) Expand(ctx context.Context, domain string) *Expansion {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))

	c.mu.Lock()
	if entry, ok := c.cache[domain]; ok && time.Now().Before(entry.expires) {
		c.mu.Unlock()
		return entry.exp
	}
	c.mu.Unlock()

	exp := c.resolve(ctx, domain)

	c.mu.Lock()
	c.cache[domain] = &cached{exp: exp, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()

	return exp
}

// Classify buckets one source address.
//
// dkimAligned and spfAligned are the receiver's own evaluated results, not ours
// to recompute: the receiver saw the message and we did not.
func (c *Classifier) Classify(ctx context.Context, domain string, addr netip.Addr, dkimAligned, spfAligned bool) Class {
	for _, prefix := range c.overrides {
		if prefix.Contains(addr.Unmap()) {
			return ClassSelf
		}
	}

	exp := c.Expand(ctx, domain)
	if exp.Authorizes(addr) {
		return ClassSelf
	}

	// An aligned DKIM signature from an address we never authorized is mail
	// that left us intact and was relayed. Counting it as unknown would bury
	// the genuinely unauthorized senders under mailing list traffic.
	if dkimAligned && !spfAligned {
		return ClassForwarder
	}

	return ClassUnknown
}

func (c *Classifier) resolve(ctx context.Context, domain string) *Expansion {
	exp := &Expansion{Domain: domain}
	if domain == "" {
		exp.Err = fmt.Errorf("empty domain")
		return exp
	}

	record, err := c.lookupSPF(ctx, domain)
	if err != nil {
		exp.Err = err
		return exp
	}

	lookups := 0
	visited := map[string]bool{domain: true}
	c.expandInto(ctx, exp, record, domain, &lookups, visited)
	exp.Lookups = lookups
	if lookups > maxLookups {
		exp.Exceeded = true
	}
	return exp
}

// lookupSPF finds the single v=spf1 record for a domain. A domain publishing
// more than one is a permerror at receivers; we take the first and let the
// lookup count surface the misconfiguration separately.
func (c *Classifier) lookupSPF(ctx context.Context, domain string) (string, error) {
	records, err := c.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("lookup spf for %q: %w", domain, err)
	}
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=spf1") {
			return record, nil
		}
	}
	return "", fmt.Errorf("no spf record for %q", domain)
}

// expandInto walks one SPF record, appending authorized prefixes.
//
// Only pass-qualified mechanisms contribute. A "-include" or "~a" narrows the
// result at a receiver rather than authorizing anything, so treating it as
// authorization would classify a spoofer as one of us.
func (c *Classifier) expandInto(ctx context.Context, exp *Expansion, record, domain string, lookups *int, visited map[string]bool) {
	for _, term := range strings.Fields(record) {
		if *lookups > maxLookups {
			return
		}
		if strings.EqualFold(term, "v=spf1") {
			continue
		}

		// Modifiers are name=value; redirect is the only one that expands.
		if name, value, ok := strings.Cut(term, "="); ok && !strings.Contains(name, ":") {
			if strings.EqualFold(name, "redirect") {
				*lookups++
				if *lookups > maxLookups || visited[strings.ToLower(value)] {
					continue
				}
				visited[strings.ToLower(value)] = true
				if next, err := c.lookupSPF(ctx, value); err == nil {
					c.expandInto(ctx, exp, next, value, lookups, visited)
				}
			}
			continue
		}

		qualifier := "+"
		switch term[0] {
		case '+', '-', '~', '?':
			qualifier = string(term[0])
			term = term[1:]
		}

		// A mechanism may carry a dual CIDR length: "a:host/24//64" applies /24
		// to the IPv4 addresses it resolves and /64 to the IPv6 ones. The
		// lengths hang off the end of the whole term, not off the mechanism
		// name, and for ip4/ip6 the same slash is the address prefix instead.
		name, v4cidr, v6cidr := splitCIDR(term)

		mechanism, argument, _ := strings.Cut(name, ":")
		mechanism = strings.ToLower(mechanism)

		if strings.EqualFold(mechanism, "all") {
			exp.All = qualifier
			continue
		}

		// Count the DNS cost even for mechanisms we will not credit, because
		// receivers count them too and that is what blows the limit.
		switch mechanism {
		case "include", "a", "mx", "ptr", "exists":
			*lookups++
			if *lookups > maxLookups {
				return
			}
		}

		if qualifier != "+" {
			continue
		}

		switch mechanism {
		case "ip4", "ip6":
			target := argument
			if v4cidr != "" {
				target += "/" + v4cidr
			}
			if prefix, err := parsePrefix(target); err == nil {
				exp.Prefixes = append(exp.Prefixes, prefix)
			}

		case "a":
			target := argument
			if target == "" {
				target = domain
			}
			c.appendHostPrefixes(ctx, exp, target, v4cidr, v6cidr)

		case "mx":
			target := argument
			if target == "" {
				target = domain
			}
			records, err := c.resolver.LookupMX(ctx, target)
			if err != nil {
				continue
			}
			for _, mx := range records {
				c.appendHostPrefixes(ctx, exp, strings.TrimSuffix(mx.Host, "."), v4cidr, v6cidr)
			}

		case "include":
			if argument == "" || visited[strings.ToLower(argument)] {
				continue
			}
			visited[strings.ToLower(argument)] = true
			next, err := c.lookupSPF(ctx, argument)
			if err != nil {
				continue
			}
			c.expandInto(ctx, exp, next, argument, lookups, visited)

		case "ptr", "exists":
			// ptr is deprecated and reverse-lookup based; exists is a runtime
			// macro expansion. Neither enumerates to a set of addresses.
		}
	}
}

// splitCIDR separates a term from its trailing CIDR lengths, returning the
// bare term, the IPv4 length and the IPv6 length.
func splitCIDR(term string) (name, v4cidr, v6cidr string) {
	name = term
	if i := strings.Index(name, "//"); i >= 0 {
		name, v6cidr = name[:i], name[i+2:]
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name, v4cidr = name[:i], name[i+1:]
	}
	return name, v4cidr, v6cidr
}

func (c *Classifier) appendHostPrefixes(ctx context.Context, exp *Expansion, host, v4cidr, v6cidr string) {
	addrs, err := c.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return
	}
	for _, ip := range addrs {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()

		cidr := v4cidr
		if addr.Is6() {
			cidr = v6cidr
		}

		bits := addr.BitLen()
		if cidr != "" {
			// An out-of-range length is treated as absent rather than silently
			// widening the prefix, which would authorize hosts the operator
			// never listed.
			if n, err := strconv.Atoi(cidr); err == nil && n >= 0 && n <= bits {
				bits = n
			}
		}
		if prefix, err := addr.Prefix(bits); err == nil {
			exp.Prefixes = append(exp.Prefixes, prefix)
		}
	}
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
