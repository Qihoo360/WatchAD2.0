package ntlmgen

import (
	"encoding/hex"
	"unsafe"
)

func Ntlmgen(startkey string) string {

	const INIT_A uint32 = 0x67452301
	const INIT_B uint32 = 0xefcdab89
	const INIT_C uint32 = 0x98badcfe
	const INIT_D uint32 = 0x10325476

	const SQRT_2 uint32 = 0x5a827999
	const SQRT_3 uint32 = 0x6ed9eba1

	var output [4]uint32

	output[0] = INIT_A
	output[1] = INIT_B
	output[2] = INIT_C
	output[3] = INIT_D

	num_blocks := len(startkey)/32 + 1
	remainder := len(startkey) % 32

	// Hash rounds
	var a uint32
	var b uint32
	var c uint32
	var d uint32

	for ii := 0; ii < num_blocks; ii++ {
		var key string
		var nt_buffer [16]uint32

		a = output[0]
		b = output[1]
		c = output[2]
		d = output[3]

		if ii+1 == num_blocks {
			key = startkey[32*ii : 32*ii+remainder]
			nt_buffer[14] = uint32(len(startkey)) << 4
		} else {
			key = startkey[32*ii : 32*ii+32]
		}

		length := uint32(len(key))

		var i uint32
		i = 0

		// This looks like little endian utf-16 conversion
		// We should do this better
		for i = 0; i < length/2; i++ {
			nt_buffer[i] = uint32(key[2*i]) | uint32(key[2*i+1])<<16
		}

		if i < 16 {
			if length%2 == 1 {
				nt_buffer[i] = uint32(key[length-1]) | 0x800000
			} else {
				nt_buffer[i] = 0x80
			}
		}

		// Round 1
		a += (d ^ (b & (c ^ d))) + nt_buffer[0]
		a = (a << 3) | (a >> 29)

		d += (c ^ (a & (b ^ c))) + nt_buffer[1]
		d = (d << 7) | (d >> 25)

		c += (b ^ (d & (a ^ b))) + nt_buffer[2]
		c = (c << 11) | (c >> 21)

		b += (a ^ (c & (d ^ a))) + nt_buffer[3]
		b = (b << 19) | (b >> 13)

		a += (d ^ (b & (c ^ d))) + nt_buffer[4]
		a = (a << 3) | (a >> 29)

		d += (c ^ (a & (b ^ c))) + nt_buffer[5]
		d = (d << 7) | (d >> 25)

		c += (b ^ (d & (a ^ b))) + nt_buffer[6]
		c = (c << 11) | (c >> 21)

		b += (a ^ (c & (d ^ a))) + nt_buffer[7]
		b = (b << 19) | (b >> 13)

		a += (d ^ (b & (c ^ d))) + nt_buffer[8]
		a = (a << 3) | (a >> 29)

		d += (c ^ (a & (b ^ c))) + nt_buffer[9]
		d = (d << 7) | (d >> 25)

		c += (b ^ (d & (a ^ b))) + nt_buffer[10]
		c = (c << 11) | (c >> 21)

		b += (a ^ (c & (d ^ a))) + nt_buffer[11]
		b = (b << 19) | (b >> 13)

		a += (d ^ (b & (c ^ d))) + nt_buffer[12]
		a = (a << 3) | (a >> 29)

		d += (c ^ (a & (b ^ c))) + nt_buffer[13]
		d = (d << 7) | (d >> 25)

		c += (b ^ (d & (a ^ b))) + nt_buffer[14]
		c = (c << 11) | (c >> 21)

		b += (a ^ (c & (d ^ a))) + nt_buffer[15]
		b = (b << 19) | (b >> 13)

		// Round 2
		a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2
		a = (a << 3) | (a >> 29)

		d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2
		d = (d << 5) | (d >> 27)

		c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2
		c = (c << 9) | (c >> 23)

		b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2
		b = (b << 13) | (b >> 19)

		a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2
		a = (a << 3) | (a >> 29)

		d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2
		d = (d << 5) | (d >> 27)

		c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2
		c = (c << 9) | (c >> 23)

		b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2
		b = (b << 13) | (b >> 19)

		a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2
		a = (a << 3) | (a >> 29)

		d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2
		d = (d << 5) | (d >> 27)

		c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2
		c = (c << 9) | (c >> 23)

		b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2
		b = (b << 13) | (b >> 19)

		a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2
		a = (a << 3) | (a >> 29)

		d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2
		d = (d << 5) | (d >> 27)

		c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2
		c = (c << 9) | (c >> 23)

		b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2
		b = (b << 13) | (b >> 19)

		// Round 3
		a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3
		a = (a << 3) | (a >> 29)

		d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3
		d = (d << 9) | (d >> 23)

		c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3
		c = (c << 11) | (c >> 21)

		b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3
		b = (b << 15) | (b >> 17)

		a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3
		a = (a << 3) | (a >> 29)

		d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3
		d = (d << 9) | (d >> 23)

		c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3
		c = (c << 11) | (c >> 21)

		b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3
		b = (b << 15) | (b >> 17)

		a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3
		a = (a << 3) | (a >> 29)

		d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3
		d = (d << 9) | (d >> 23)

		c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3
		c = (c << 11) | (c >> 21)

		b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3
		b = (b << 15) | (b >> 17)

		a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3
		a = (a << 3) | (a >> 29)

		d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3
		d = (d << 9) | (d >> 23)

		c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3
		c = (c << 11) | (c >> 21)

		b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3
		b = (b << 15) | (b >> 17)

		output[0] += a
		output[1] += b
		output[2] += c
		output[3] += d
	}

	pf := (*[16]byte)(unsafe.Pointer(&output))[:]

	return hex.EncodeToString(pf)

}
