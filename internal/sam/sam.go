// Package sam parses and decrypts local account hashes from SAM+SYSTEM
// registry hive bytes, secretsdump-style. It is pure (no I/O, no network):
// all hive access happens via gopacket's pkg/registry on caller-supplied
// bytes.
package sam

import (
	"encoding/hex"
	"fmt"

	"github.com/mandiant/gopacket/pkg/registry"
)

// User is one local account from a SAM hive.
type User struct {
	Username string
	RID      uint32
	NTHash   []byte
	LMHash   []byte
	Enabled  bool
}

// Dump parses SYSTEM and SAM hive bytes, derives the boot key from SYSTEM,
// and decrypts every local account's NT/LM hashes from SAM. Hashes that are
// absent are reported as the well-known empty-LM/empty-NT constants (as
// tools/secretsdump does).
func Dump(systemData, samData []byte) ([]User, error) {
	systemHive, err := registry.Open(systemData)
	if err != nil {
		return nil, fmt.Errorf("parse SYSTEM hive: %v", err)
	}
	samHive, err := registry.Open(samData)
	if err != nil {
		return nil, fmt.Errorf("parse SAM hive: %v", err)
	}

	bootKey, err := registry.GetBootKey(systemHive)
	if err != nil {
		return nil, fmt.Errorf("derive boot key: %v", err)
	}

	users, err := registry.DumpSAM(samHive, bootKey)
	if err != nil {
		return nil, err
	}

	out := make([]User, 0, len(users))
	for _, u := range users {
		nt := u.NTHash
		if len(nt) != 16 {
			nt = registry.EmptyNTHash
		}
		lm := u.LMHash
		if len(lm) != 16 {
			lm = registry.EmptyLMHash
		}
		out = append(out, User{
			Username: u.Username,
			RID:      u.RID,
			NTHash:   nt,
			LMHash:   lm,
			Enabled:  u.Enabled,
		})
	}
	return out, nil
}

// Format renders one user in secretsdump format: user:RID:lmHex:ntHex:::
func Format(u User) string {
	return fmt.Sprintf("%s:%d:%s:%s:::",
		u.Username, u.RID, hex.EncodeToString(u.LMHash), hex.EncodeToString(u.NTHash))
}
