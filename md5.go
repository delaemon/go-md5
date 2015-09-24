package md5
import "math"

var (
	DigestBufLen [4]uint32
	WorkBufLen   [16]uint32
	MsgBlockLen  [64]uint32
	K [64]uint32

	h0 uint32 = 0x67452301
	h1 uint32 = 0xefcdab89
	h2 uint32 = 0x98badcfe
	h3 uint32 = 0x10325476
)

func Md5(input string) string {
	for i := 0; i < 64; i++ {
		K[i] = math.Floor(math.Abs(math.Sin(i + 1)) * (2 ** 32))
	}

	var block [MsgBlockLen]uint8{}
	i := 0
	for _, msg := range input {
		block[i] = msg
		if i == MsgBlockLen {
			processMsgBlock(block)
			block = [MsgBlockLen]uint8{}
			i = 0
		}
	}

	return " "
}

func processMsgBlock(block []uint8) {
	x := WorkBufLen
	m := block
	var xi uint32 = 0
	var mi uint32 = 0
	var ki uint32 = 0
	for xi < uint32(16) {
		x[xi] = (uint32(m[mi]) |
		(uint32(m[mi+uint32(1)]) << 8) |
		(uint32(m[mi+uint32(2)]) << 16) |
		(uint32(m[mi+uint32(3)]) << 24))
		xi += uint32(1)
		mi += uint32(4)
	}

	a := h0
	b := h1
	c := h2
	d := h3

	// Round 1
	// F(X, Y, Z) = XY v not(X) Z
	i := 0
	for i < 16 {
		a = b + leftRotate(7, a + ((b & c) | (!b & d) + x[i] + K[i]))
		i += 1
		d = a + leftRotate(12, d + ((a & b) | (!a & c) + x[i] + K[i]))
		i += 1
		c = d + leftRotate(17, c + ((d & a) | (!d & b) + x[i] + K[i]))
		i += 1
		b = c + leftRotate(22, a + ((c & d) | (!c & a) + x[i] + K[i]))
		i += 1
	}

	// Round 2
	// G(X,Y,Z) = XZ v Y not(Z)
	xi = 1
	ki = 16
	for ki < 32 {
		a = b + leftRotate( 5, a + ((b & d) | (c & !d)) + x[xi] + K[ki])
		xi = (xi + 5) & 0xF
		d = a + leftRotate( 9, d + ((a & c) | (b & !c)) + x[xi] + K[ki+1])
		xi = (xi + 5) & 0xF
		c = d + leftRotate(14, c + ((d & b) | (a & !b)) + x[xi] + K[ki+2])
		xi = (xi + 5) & 0xF
		b = c + leftRotate(20, b + ((c & a) | (d & !a)) + x[xi] + K[ki+3])
		xi = (xi + 5) & 0xF
		ki += 4
	}

	// Round 3
	// H(X,Y,Z) = X xor Y xor Z
	xi = 5
	for ki < 48 {
		a = b + leftRotate( 4, a + (b ^ c ^ d) + x[xi] + K[ki])
		xi = (xi + 3) & 0xF
		d = a + leftRotate(11, d + (a ^ b ^ c) + x[xi] + K[ki+1])
		xi = (xi + 3) & 0xF
		c = d + leftRotate(16, c + (d ^ a ^ b) + x[xi] + K[ki+2])
		xi = (xi + 3) & 0xF
		b = c + leftRotate(23, b + (c ^ d ^ a) + x[xi] + K[ki+3])
		xi = (xi + 3) & 0xF
		ki += 4
	}

	// Round 4
	// I(X,Y,Z) = Y xor (X v not(Z))
	xi = 0;
	for ki < 64 {
		a = b + leftRotate( 6, a + (c ^ (b | !d)) + x[xi] + K[ki])
		xi = (xi + 7) & 0xF
		d = a + leftRotate(10, d + (b ^ (a | !c)) + x[xi] + K[ki+1])
		xi = (xi + 7) & 0xF
		c = d + leftRotate(15, c + (a ^ (d | !b)) + x[xi] + K[ki+2])
		xi = (xi + 7) & 0xF
		b = c + leftRotate(21, b + (d ^ (c | !a)) + x[xi] + K[ki+3])
		xi = (xi + 7) & 0xF
		ki += 4
	}

	// Update the buffer
	h0 += a
	h1 += b
	h2 += c
	h3 += d
}

func leftRotate(x uint32, r int) uint32 {
	rr := uint32(r)
	return ((x << rr) | (x >> (32 - rr))) & 0xffffffff
}
