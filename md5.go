package md5
import (
	"fmt"
)

func leftRotate(x uint32, r int) uint32 {
	var rr uint32 = uint32(r)
	return ((x << rr) | (x >> (32 - rr))) & 0xffffffff
}

func Md5(message string) string {
	//Note: All variables are unsigned 32 bit and wrap modulo 2^32 when calculating

	// s specifies the per-round shift amounts
	s := []int{ 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22, //  0..15
				5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20, // 16..31
				4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23, // 32..47
				6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21} // 48..63

	// Use binary integer part of the sines of integers (Radians) as constants:
	//for i = 0; i < 64; i++ {
	//	K[i] = uint32(math.Floor(math.Abs(math.Sin(float64(i+1))) * (math.Pow(2, 32))))
	//}
	// (Or just use the following table):
	K := []uint32{	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, // 0.. 3
					0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, // 4.. 7
					0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, // 8..11
					0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, //12..15
					0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, //16..19
					0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, //20..23
					0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, //24..27
					0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, //28..31
					0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, //32..35
					0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, //36..39
					0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, //40..43
					0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, //44..47
					0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, //48..51
					0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, //52..55
					0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, //56..59
					0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391} //60..63

	// Initialize variables:
	var a0 uint32 = 0x67452301 // A
	var b0 uint32 = 0xefcdab89 // B
	var c0 uint32 = 0x98badcfe // C
	var d0 uint32 = 0x10325476 // D

	// Pre-processing:
	chunk := []byte(message)

	// Pre-processing: adding a single 1 bit
	chunk = append(chunk, byte(0x80))

	// Pre-processing: padding with zeros
	padding := 64 - (len(message) + 1) % 64
	for i := 0; i < padding; i++ {
		chunk = append(chunk, 0x00)
	}
	m := [16]uint32{}
	x := chunk
	xi := 0
	mi := 0
	for mi < 16 {
		m[mi] = (uint32(x[xi]) |
		(uint32(x[xi+1]) << 8) |
		(uint32(x[xi+2]) << 16) |
		(uint32(x[xi+3]) << 24))
		mi += 1
		xi += 4
	}

	// Initialize hash value for this chunk:
	a := a0
	b := b0
	c := c0
	d := d0
	var f uint32
	var g int
	for i, _ := range chunk {
		if i < 16 {
			f = uint32((b & c) | ((^b) & d))
			g = i
		} else if i < 32 {
			f = uint32((b & d) | ((^d) & c))
			g = 5 * i % 16
		} else if i < 47 {
			f = uint32((b ^ c ^ d))
			g = (3 * i + 5) % 16
		} else if i < 63 {
			f = uint32((c ^ (b | (^d))))
			g = 7 * i % 16
		}
		tmp := d
		d = c
		c = b
		b = b + leftRotate((a + f + K[i] + m[g]), s[i])
		a = tmp
	}
	a0 += a0 + a
	b0 += b0 + b
	c0 += c0 + c
	d0 += d0 + d

	return fmt.Sprintf("%x%x%x%x", a0, b0, c0, d0)
}