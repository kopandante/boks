package config

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// keyTypes are the ssh public key types a deploy key may be.
var keyTypes = []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"}

// DeployKey is an ssh public key as it goes into authorized_keys: its type and its base64, the comment
// dropped. Anything else in it — options before the type, a second line, a blob whose own type is not
// the one written — is refused: authorized_keys reads options and lines, and a key that carried either
// could undo the forced command it is bound to.
func DeployKey(key string) (string, error) {
	fields := strings.Fields(key)
	if strings.ContainsAny(key, "\r\n") || len(fields) < 2 {
		return "", errors.New("one line: the key's type, its base64, and a comment if any")
	}
	typ, b64 := fields[0], fields[1]
	if !slices.Contains(keyTypes, typ) {
		return "", fmt.Errorf("type %q is none of %s (options before the type are not allowed)", typ, strings.Join(keyTypes, ", "))
	}
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("the key is not base64: %w", err)
	}
	// The blob opens with its own type, as an ssh string: a 4-byte length, then the name.
	if len(blob) < 4 || int(binary.BigEndian.Uint32(blob)) != len(typ) || len(blob) < 4+len(typ) || string(blob[4:4+len(typ)]) != typ {
		return "", fmt.Errorf("the key's data is not a %s key", typ)
	}
	return typ + " " + b64, nil
}
