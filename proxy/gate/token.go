package gate

// The sites' API token, as cars-cli's registry/lib/security/api-token.ts makes and checks it:
// base64url(JSON{iat, nonce, fp?, ip?}) "." base64url(HMAC-SHA256(the first part, secret)), valid for
// three minutes from iat, in milliseconds. The proxy and a site that still checks tokens itself take
// each other's: a group's secret is its site's API_SECRET_CURRENT.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// tokenTTL is api-token.ts's TOKEN_TTL_MS: a token of that age still passes, a millisecond older not.
const tokenTTL = 3 * time.Minute

// payload is what the gate reads of a token. fp and ip are empty when the token has none, and also
// when it has no nonce: the site's extractTokenPayload returns null for such a token, and its gate
// then compares neither.
type payload struct {
	fp, ip string
}

// claims is the payload as the proxy writes it, in createApiToken's order.
type claims struct {
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	FP    string `json:"fp,omitempty"`
	IP    string `json:"ip,omitempty"`
}

func signature(encoded, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// sign issues a token with the group's current secret.
func (h *Handler) sign(fp, ip string) string {
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce) // never fails: crypto/rand panics rather than return an error
	b, _ := json.Marshal(claims{Iat: h.now().UnixMilli(), Nonce: hex.EncodeToString(nonce), FP: fp, IP: ip})
	enc := base64.RawURLEncoding.EncodeToString(b)
	return enc + "." + signature(enc, h.Secrets[0])
}

// decodePayload reads the first part of a token. Strict where Node is lenient: Buffer.from(…,
// "base64url") also takes padding and the standard alphabet, which createApiToken never writes, so
// such a token is one made by hand with the secret (AC1, class stricter).
func decodePayload(enc string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(enc)
}

// verify checks a token's signature against each of the group's secrets, then its age, and says why
// it fails: bad_format, bad_signature, bad_payload or expired; "" for a token that passes. An expired
// token still comes with its payload: its fingerprint, signed, is the client's to keep on renewal. The
// signature is compared as the string createApiToken writes — a token signed right but encoded
// otherwise fails, where Node decodes both sides first.
func (h *Handler) verify(tok string, now time.Time) (payload, string) {
	dot := strings.IndexByte(tok, '.')
	if dot <= 0 || dot == len(tok)-1 {
		return payload{}, "bad_format"
	}
	enc, sig := tok[:dot], tok[dot+1:]
	signed := false
	for _, s := range h.Secrets {
		if hmac.Equal([]byte(sig), []byte(signature(enc, s))) {
			signed = true
			break
		}
	}
	if !signed {
		return payload{}, "bad_signature"
	}
	raw, err := decodePayload(enc)
	if err != nil {
		return payload{}, "bad_format"
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return payload{}, "bad_payload"
	}
	var iat float64
	if v, ok := fields["iat"]; !ok || string(v) == "null" || json.Unmarshal(v, &iat) != nil {
		return payload{}, "bad_payload"
	}
	var p payload
	var nonce string
	if v, ok := fields["nonce"]; ok && string(v) != "null" && json.Unmarshal(v, &nonce) == nil {
		for name, dst := range map[string]*string{"fp": &p.fp, "ip": &p.ip} {
			v, ok := fields[name]
			if !ok || string(v) == "null" {
				continue
			}
			// A value that is no string the sites never write; the proxy refuses what a site would compare.
			if json.Unmarshal(v, dst) != nil {
				return payload{}, "bad_payload"
			}
		}
	}
	if age := float64(now.UnixMilli()) - iat; age < 0 || age > float64(tokenTTL.Milliseconds()) {
		return p, "expired"
	}
	return p, ""
}
