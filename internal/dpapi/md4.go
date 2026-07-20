package dpapi

import "encoding/binary"

// md4Sum is a minimal one-shot MD4 (RFC 1320). MD4 is collision-broken and
// must never be used for new designs, but the Windows NT password hash —
// and therefore impacket's DPAPI user-key derivation — is defined as
// MD4(utf16le(password)). golang.org/x/crypto/md4 would do, but x/crypto is
// only an indirect dependency of this module and keeping it that way lets
// this package stay dependency-neutral; MD4 is small enough to carry inline
// (verified against the RFC 1320 test suite in userkey_test.go).
func md4Sum(data []byte) (digest [16]byte) {
	// Padding: 0x80, zeros to 56 mod 64, 8-byte LE bit length.
	bitLen := uint64(len(data)) * 8
	msg := make([]byte, 0, len(data)+72)
	msg = append(msg, data...)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	var lb [8]byte
	binary.LittleEndian.PutUint64(lb[:], bitLen)
	msg = append(msg, lb[:]...)

	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)
	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	rot := func(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }

	// Per RFC 1320: round 2 and 3 permute the message-word order.
	seq1 := [16]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	seq2 := [16]int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	seq3 := [16]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}

	for i := 0; i < len(msg); i += 64 {
		var x [16]uint32
		for j := range x {
			x[j] = binary.LittleEndian.Uint32(msg[i+4*j:])
		}
		aa, bb, cc, dd := a, b, c, d
		round := func(fn func(uint32, uint32, uint32) uint32, seq [16]int, shifts [4]uint, cnst uint32) {
			for j, k := range seq {
				switch j % 4 {
				case 0:
					a = rot(a+fn(b, c, d)+x[k]+cnst, shifts[0])
				case 1:
					d = rot(d+fn(a, b, c)+x[k]+cnst, shifts[1])
				case 2:
					c = rot(c+fn(d, a, b)+x[k]+cnst, shifts[2])
				case 3:
					b = rot(b+fn(c, d, a)+x[k]+cnst, shifts[3])
				}
			}
		}
		round(f, seq1, [4]uint{3, 7, 11, 19}, 0)
		round(g, seq2, [4]uint{3, 5, 9, 13}, 0x5a827999)
		round(h, seq3, [4]uint{3, 9, 11, 15}, 0x6ed9eba1)
		a += aa
		b += bb
		c += cc
		d += dd
	}

	binary.LittleEndian.PutUint32(digest[0:4], a)
	binary.LittleEndian.PutUint32(digest[4:8], b)
	binary.LittleEndian.PutUint32(digest[8:12], c)
	binary.LittleEndian.PutUint32(digest[12:16], d)
	return digest
}
