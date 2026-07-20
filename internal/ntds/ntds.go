// Package ntds parses and decrypts domain account hashes from NTDS.dit
// (ESE database) bytes plus the SYSTEM hive that holds the boot key,
// secretsdump-style. It is pure (no I/O, no network): all parsing happens
// via gopacket's pkg/ese and pkg/registry on caller-supplied bytes.
package ntds

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/ese"
	"github.com/mandiant/gopacket/pkg/registry"
)

// User is one domain account from an NTDS.dit database.
type User struct {
	Name   string
	RID    uint32
	NTHash []byte
	LMHash []byte
}

// ESE column names for the AD attributes (fixed schema ATT ids, as used by
// tools/secretsdump's offline NTDS path).
const (
	colSAMAccountName = "ATTm590045" // sAMAccountName
	colObjectSID      = "ATTr589970" // objectSid
	colDBCSPwd        = "ATTk589913" // dBCSPwd (encrypted LM hash)
	colUnicodePwd     = "ATTk589914" // unicodePwd (encrypted NT hash)
	colPEKList        = "ATTk590689" // pekList
)

// Dump parses NTDS.dit and SYSTEM hive bytes, derives the boot key from
// SYSTEM, decrypts the PEK (password encryption key) found in the
// datatable, and decrypts every account's NT/LM hashes. Hashes that are
// absent or fail to decrypt are reported as the well-known
// empty-LM/empty-NT constants (as tools/secretsdump does).
func Dump(ntdsData, systemData []byte) ([]User, error) {
	systemHive, err := registry.Open(systemData)
	if err != nil {
		return nil, fmt.Errorf("parse SYSTEM hive: %v", err)
	}
	bootKey, err := registry.GetBootKey(systemHive)
	if err != nil {
		return nil, fmt.Errorf("derive boot key: %v", err)
	}

	db, err := ese.Open(ntdsData)
	if err != nil {
		return nil, fmt.Errorf("parse NTDS.dit: %v", err)
	}
	datatable, err := db.OpenTable("datatable")
	if err != nil {
		return nil, fmt.Errorf("open datatable: %v", err)
	}

	pek, err := extractPEK(datatable, bootKey)
	if err != nil {
		return nil, fmt.Errorf("extract PEK: %v", err)
	}

	var users []User
	for i := 0; i < datatable.NumRecords(); i++ {
		record, err := datatable.GetRecord(i)
		if err != nil {
			continue
		}

		name := record.GetColumnString(colSAMAccountName)
		if name == "" {
			continue
		}
		sid := record.GetColumn(colObjectSID)
		if len(sid) < 8 {
			continue
		}
		rid := ridFromSID(sid)

		nt := decryptHash(record.GetColumn(colUnicodePwd), pek, rid)
		if len(nt) != 16 {
			nt = registry.EmptyNTHash
		}
		lm := decryptHash(record.GetColumn(colDBCSPwd), pek, rid)
		if len(lm) != 16 {
			lm = registry.EmptyLMHash
		}
		users = append(users, User{Name: name, RID: rid, NTHash: nt, LMHash: lm})
	}
	return users, nil
}

// Format renders one account in secretsdump format: DOMAIN\user:RID:lm:nt:::
// A missing hash renders as the empty-hash constant (secretsdump behavior
// for accounts with no stored LM/NT hash); Dump already substitutes these,
// so the fallback only fires for hand-built Users.
func Format(domain string, u User) string {
	lm, nt := u.LMHash, u.NTHash
	if len(lm) == 0 {
		lm = registry.EmptyLMHash
	}
	if len(nt) == 0 {
		nt = registry.EmptyNTHash
	}
	return fmt.Sprintf("%s\\%s:%d:%s:%s:::",
		domain, u.Name, u.RID, hex.EncodeToString(lm), hex.EncodeToString(nt))
}

// Domain best-effort derives the domain's NetBIOS name from the SYSTEM
// hive's TCP/IP parameters (the DNS domain, first label upper-cased — the
// same derivation tools/secretsdump applies to the credentials' domain).
// Returns "" when the hive lacks the value.
func Domain(systemData []byte) string {
	hive, err := registry.Open(systemData)
	if err != nil {
		return ""
	}
	controlSet, err := registry.GetCurrentControlSet(hive)
	if err != nil {
		return ""
	}
	keyOffset, err := hive.FindKey(controlSet + `\Services\Tcpip\Parameters`)
	if err != nil {
		return ""
	}
	for _, valueName := range []string{"Domain", "NV Domain"} {
		_, data, err := hive.GetValue(keyOffset, valueName)
		if err != nil {
			continue
		}
		if d := decodeUTF16(data); d != "" {
			return strings.ToUpper(strings.Split(d, ".")[0])
		}
	}
	return ""
}

// ridFromSID extracts the RID (last sub-authority) from an objectSid blob.
// In NTDS.dit the RID bytes are stored big-endian (tools/secretsdump).
func ridFromSID(sid []byte) uint32 {
	return binary.BigEndian.Uint32(sid[len(sid)-4:])
}

// extractPEK finds the pekList attribute in the datatable and decrypts it
// with the boot key.
func extractPEK(datatable *ese.Table, bootKey []byte) ([]byte, error) {
	for i := 0; i < datatable.NumRecords(); i++ {
		record, err := datatable.GetRecord(i)
		if err != nil {
			continue
		}
		encPEK := record.GetColumn(colPEKList)
		if len(encPEK) == 0 {
			continue
		}
		return decryptPEK(encPEK, bootKey)
	}
	return nil, fmt.Errorf("pekList not found in datatable")
}

// decryptPEK decrypts the encrypted PEKLIST blob with the boot key:
// version 3 is AES-CBC with the boot key directly (Windows Server 2016+),
// anything else is RC4 with MD5(bootKey || salt x1000). Mirrors
// tools/secretsdump's decryptPEK.
func decryptPEK(encPEK, bootKey []byte) ([]byte, error) {
	if len(encPEK) < 44 {
		return nil, fmt.Errorf("encrypted PEK too short: %d", len(encPEK))
	}

	// PEKLIST_ENC: header(8) | keyMaterial/salt(16) | encryptedPek
	version := binary.LittleEndian.Uint32(encPEK[0:4])
	keyMaterial := encPEK[8:24]
	encData := encPEK[24:]

	if version == 3 {
		// AES-CBC with the boot key as key, keyMaterial as IV.
		decrypted, err := aesCBCDecrypt(bootKey, keyMaterial, encData)
		if err != nil {
			return nil, err
		}
		// PEKLIST_PLAIN: header(32) | entries of index(4) + pek(16).
		if len(decrypted) < 52 {
			return nil, fmt.Errorf("decrypted PEK blob too short: %d", len(decrypted))
		}
		entries := decrypted[32:]
		if index := binary.LittleEndian.Uint32(entries[0:4]); index != 0 {
			return nil, fmt.Errorf("unexpected PEK index: %d", index)
		}
		return entries[4:20], nil
	}

	// RC4: key is MD5(bootKey || salt x1000); PEK sits at offset 36.
	key := registry.MD5With1000Rounds(bootKey, keyMaterial)
	decrypted := registry.RC4Decrypt(key, encData)
	if len(decrypted) < 52 {
		return nil, fmt.Errorf("decrypted PEK too short: %d", len(decrypted))
	}
	return decrypted[36:52], nil
}

// decryptHash decrypts one stored hash (unicodePwd/dBCSPwd value): first
// the PEK layer, then the RID-based DES layer. Returns nil on any failure —
// the caller substitutes the empty-hash constant.
func decryptHash(encHash, pek []byte, rid uint32) []byte {
	plain, err := decryptWithPEK(encHash, pek)
	if err != nil || len(plain) < 16 {
		return nil
	}
	hash, err := registry.DecryptNTDSHashWithRID(plain[:16], rid)
	if err != nil {
		return nil
	}
	return hash
}

// decryptWithPEK strips the outer PEK encryption from a stored hash:
// version 0x13 (19) is AES-CBC with the PEK (Windows Server 2016+),
// version 1 is RC4 with MD5(pek || keyMaterial). Mirrors
// tools/secretsdump's decryptWithPEK.
func decryptWithPEK(data, pek []byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("data too short for PEK decryption: %d", len(data))
	}

	version := binary.LittleEndian.Uint32(data[0:4])
	keyMaterial := data[8:24]

	if version == 0x13 {
		// CRYPTED_HASHW16: header(8) | keyMaterial(16) | unknown(4) | encHash
		if len(data) < 44 {
			return nil, fmt.Errorf("encrypted hash too short for AES path: %d", len(data))
		}
		encHash := data[28:]
		if len(encHash) < 16 {
			return nil, fmt.Errorf("encrypted hash too short: %d", len(encHash))
		}
		return aesCBCDecrypt(pek, keyMaterial, encHash[:16])
	}

	// CRYPTED_HASH: header(8) | keyMaterial(16) | encHash
	if len(data) < 40 {
		return nil, fmt.Errorf("encrypted hash too short for RC4 path: %d", len(data))
	}
	h := md5.New()
	h.Write(pek)
	h.Write(keyMaterial)
	decrypted := registry.RC4Decrypt(h.Sum(nil), data[24:])
	if len(decrypted) < 16 {
		return nil, fmt.Errorf("decrypted hash too short: %d", len(decrypted))
	}
	return decrypted[:16], nil
}

// aesCBCDecrypt decrypts data in place-length with AES-CBC (no padding
// handling — the NTDS blobs are always block-aligned).
func aesCBCDecrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data not block-aligned: %d", len(data))
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

// decodeUTF16 decodes a UTF-16LE registry string and trims trailing NULs.
func decodeUTF16(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		runes = append(runes, rune(uint16(data[i])|uint16(data[i+1])<<8))
	}
	for len(runes) > 0 && runes[len(runes)-1] == 0 {
		runes = runes[:len(runes)-1]
	}
	return string(runes)
}
