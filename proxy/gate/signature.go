package gate

// Signatures (plan docs/plans/20261030-gate-signatures.md): the shapes of headers no browser of the
// group's visitors sends, written per group from the access log of a client that does — the scraper of
// cars.dbauto.kr sends Accept-Encoding "br, gzip, deflate" under Chrome's User-Agent, which no Chrome
// does. A signature matches a request when each header it names matches its pattern: the header's
// first value, "" when it is absent, so a signature names what a client sends and no browser does as
// well as what every browser sends and the client leaves out. It is asked of every request on the
// group's hosts — pages, the token's issue and the exemptions too, as a scraper takes what it can.
//
// In log a match goes into the access log as gate_signature and nothing else changes; in enforce the
// request is refused, and with signature_ban so is its address: every request of the group from it for
// that long, gate_reason signature_ban. The addresses are kept by the process — every deploy on the
// server reloads the proxy, which keeps them — and lost on its restart. Google's and Yandex's crawlers
// and the checks' exempt_ranges are never matched nor banned.

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Signature is one shape of headers, off — the default — log or enforce.
type Signature struct {
	Name    string          `json:"name"`
	Mode    string          `json:"mode,omitempty"`
	Headers []HeaderPattern `json:"headers"`

	compiled []*regexp.Regexp
}

// HeaderPattern is a header's name and the RE2 pattern its first value matches, "" when absent.
type HeaderPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

const (
	maxSignatures = 32
	// minSignatureBan and maxSignatureBan bound signature_ban: a ban shorter than a minute is the
	// request's own refusal, one longer than a week outlives the address a home line is given.
	minSignatureBan = time.Minute
	maxSignatureBan = 7 * 24 * time.Hour
	// maxBanned bounds the addresses banned at once over every group: a day of the scraper is about
	// 1 500 of them, and an entry is under a hundred bytes.
	maxBanned = 200_000
)

var signatureName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// compile compiles the patterns of s.
func (s *Signature) compile() error {
	s.compiled = s.compiled[:0]
	for _, hp := range s.Headers {
		re, err := regexp.Compile(hp.Pattern)
		if err != nil {
			return fmt.Errorf("signatures[%s]: headers[%s]: %w", s.Name, hp.Name, err)
		}
		s.compiled = append(s.compiled, re)
	}
	return nil
}

// validate refuses a signature that is not named, has no header, or would match every request
// without its headers: one pattern at least must refuse an absent header.
func (s *Signature) validate(groupMode string) error {
	switch {
	case !signatureName.MatchString(s.Name):
		return fmt.Errorf("signatures: name %q must match %s", s.Name, signatureName)
	case s.Mode != "" && s.Mode != "off" && s.Mode != "log" && s.Mode != "enforce":
		return fmt.Errorf("signatures[%s]: mode %q must be off, log or enforce", s.Name, s.Mode)
	case s.Mode == "enforce" && groupMode != "enforce":
		return fmt.Errorf("signatures[%s]: enforce goes with the group's mode enforce", s.Name)
	case len(s.Headers) == 0:
		return fmt.Errorf("signatures[%s]: headers: at least one", s.Name)
	}
	for _, hp := range s.Headers {
		if hp.Name == "" {
			return fmt.Errorf("signatures[%s]: a header without a name", s.Name)
		}
	}
	for _, re := range s.compiled {
		if !re.MatchString("") {
			return nil
		}
	}
	return fmt.Errorf("signatures[%s]: every pattern matches an absent header, so it would match a request with none of them", s.Name)
}

// matches says whether every header of s matches its pattern.
func (s *Signature) matches(r *http.Request) bool {
	for i, hp := range s.Headers {
		if !s.compiled[i].MatchString(r.Header.Get(hp.Name)) {
			return false
		}
	}
	return true
}

func (s *Signature) on() bool { return s.Mode == "log" || s.Mode == "enforce" }

// validateSignatures checks the group's signatures and their ban.
func (h *Handler) validateSignatures() error {
	if len(h.Signatures) > maxSignatures {
		return fmt.Errorf("signatures: %d of them, more than %d", len(h.Signatures), maxSignatures)
	}
	if h.SignatureBan != 0 && len(h.Signatures) == 0 {
		return errNoSignatures
	}
	names := map[string]bool{}
	for i := range h.Signatures {
		s := &h.Signatures[i]
		if names[s.Name] {
			return fmt.Errorf("signatures[%s]: the name is used twice", s.Name)
		}
		names[s.Name] = true
		if err := s.validate(h.Mode); err != nil {
			return err
		}
	}
	if b := time.Duration(h.SignatureBan); b != 0 && (b < minSignatureBan || b > maxSignatureBan) {
		return fmt.Errorf("signature_ban %s must be from %s to %s", b, minSignatureBan, maxSignatureBan)
	}
	return nil
}

// signed is the signatures' verdict on r from ip, and whether they have one: a banned address, and a
// request an enforced signature matches, are refused; a match in log is written and passed on to the
// rest of the gate. The first signature that matches is the one written.
func (h *Handler) signed(r *http.Request, ip string) (decision, bool) {
	if len(h.Signatures) == 0 {
		return decision{}, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || h.spared(r, a) {
		return decision{}, false
	}
	now := h.now()
	if h.SignatureBan != 0 && h.banStore().banned(h.Name, a, now) {
		return deny("signature_ban", forbidden), true
	}
	s := h.matching(r)
	if s == nil {
		return decision{}, false
	}
	setField(r, zap.String("gate_signature", s.Name))
	if s.Mode != "enforce" {
		return decision{}, false
	}
	h.banAddr(r, a, s, now)
	return deny("signature", forbidden), true
}

// matching is the first signature on that matches r, nil when none does.
func (h *Handler) matching(r *http.Request) *Signature {
	for i := range h.Signatures {
		if s := &h.Signatures[i]; s.on() && s.matches(r) {
			return s
		}
	}
	return nil
}

// spared says whether a is never matched: an exempt address of the checks, Google's, Yandex's robots.
func (h *Handler) spared(r *http.Request, a netip.Addr) bool {
	return inRanges(h.checksExempt, a) || isGoogle(a) || isYandex(a, r.UserAgent())
}

// banAddr bans a for the group's signature_ban, when it has one, and writes the ban's start.
func (h *Handler) banAddr(r *http.Request, a netip.Addr, s *Signature, now time.Time) {
	if h.SignatureBan == 0 {
		return
	}
	until := now.Add(time.Duration(h.SignatureBan))
	if !h.banStore().ban(h.Name, a, until, now) {
		h.logger.Error("too many addresses banned by signature; this one is refused without a ban",
			zap.String("group", h.Name), zap.Int("max", maxBanned))
		return
	}
	h.logger.Info("address banned by signature", zap.String("group", h.Name), zap.String("signature", s.Name),
		zap.String("ip", a.String()), zap.String("host", r.Host), zap.String("path", r.URL.Path),
		zap.String("user_agent", sample(r.UserAgent())), zap.String("until", until.UTC().Format(time.RFC3339)))
}

func (h *Handler) banStore() *banStore {
	if h.bans != nil {
		return h.bans
	}
	return sharedBans
}

// sample is a User-Agent as the journal has it: its first 160 bytes.
func sample(ua string) string {
	if len(ua) > 160 {
		return ua[:160]
	}
	return ua
}

// sharedBans are the bans of every handler the process provisions: a reload's handler of a group finds
// the addresses the one it replaced banned.
var sharedBans = newBanStore()

type banKey struct {
	group string
	addr  netip.Addr
}

// banStore is the addresses banned by signature, by group, with the ban's end.
type banStore struct {
	mu    sync.Mutex
	until map[banKey]time.Time
	max   int
}

func newBanStore() *banStore { return &banStore{until: map[banKey]time.Time{}, max: maxBanned} }

// banned says whether a is banned in group at now.
func (s *banStore) banned(group string, a netip.Addr, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.until[banKey{group, a}]
	return ok && now.Before(t)
}

// ban bans a in group until then, and says whether it could: when the store is full of bans not yet
// over, the address is not kept.
func (s *banStore) ban(group string, a netip.Addr, until, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.until) >= s.max {
		s.sweep(now)
	}
	if len(s.until) >= s.max {
		return false
	}
	s.until[banKey{group, a}] = until
	return true
}

// sweep removes the bans that are over.
func (s *banStore) sweep(now time.Time) {
	for k, t := range s.until {
		if !now.Before(t) {
			delete(s.until, k)
		}
	}
}

var errNoSignatures = errors.New("signature_ban goes with signatures")
