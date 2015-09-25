package md5
import (
	"math"
	"fmt"
)

const (
	DigestBufLen int = 4
	WorkBufLen   int = 16
	MsgBlockLen  uint = 64
)

var (
	K [64]uint32
	h [4]uint32 = [4]uint32 {
					0xefcdab89,
					0x98badcfe,
					0x10325476,}
)

func appendZeros(block [MsgBlockLen]uint8, i, l uint) [MsgBlockLen]uint8 {
	for i < l {
		block[i] = 0
		i++
	}
	return block
}

func padMsgBlock(block [MsgBlockLen]uint8, i, l uint) [MsgBlockLen]uint8 {
	block[i] = 0x80
	block = appendZeros(block, i+1, l)
	return block
}

func processMsgBlock(block [MsgBlockLen]uint8) {
	x := [WorkBufLen]uint32{}
	m := block
	var xi uint32 = 0
	var mi uint32 = 0
	var ki uint32 = 0
	for xi < 16 {
		x[xi] = (uint32(m[mi]) |
		(uint32(m[mi+1]) << 8) |
		(uint32(m[mi+2]) << 16) |
		(uint32(m[mi+3]) << 24))
		xi += 1
		mi += 4
	}

	a := h[0]
	b := h[1]
	c := h[2]
	d := h[3]

	// Round 1
	// F(X, Y, Z) = XY v not(X) Z
	i := 0
	for i < 16 {
		a = b + leftRotate(7, a + ((b & c) | (^b & d) + x[i] + K[i]))
		i += 1
		d = a + leftRotate(12, d + ((a & b) | (^a & c) + x[i] + K[i]))
		i += 1
		c = d + leftRotate(17, c + ((d & a) | (^d & b) + x[i] + K[i]))
		i += 1
		b = c + leftRotate(22, a + ((c & d) | (^c & a) + x[i] + K[i]))
		i += 1
	}

	// Round 2
	// G(X,Y,Z) = XZ v Y not(Z)
	xi = 1
	ki = 16
	for ki < 32 {
		a = b + leftRotate( 5, a + ((b & d) | (c & ^d)) + x[xi] + K[ki])
		xi = (xi + 5) & 0xf
		d = a + leftRotate( 9, d + ((a & c) | (b & ^c)) + x[xi] + K[ki+1])
		xi = (xi + 5) & 0xf
		c = d + leftRotate(14, c + ((d & b) | (a & ^b)) + x[xi] + K[ki+2])
		xi = (xi + 5) & 0xf
		b = c + leftRotate(20, b + ((c & a) | (d & ^a)) + x[xi] + K[ki+3])
		xi = (xi + 5) & 0xf
		ki += 4
	}

	// Round 3
	// H(X,Y,Z) = X xor Y xor Z
	xi = 5
	for ki < 48 {
		a = b + leftRotate( 4, a + (b ^ c ^ d) + x[xi] + K[ki])
		xi = (xi + 3) & 0xf
		d = a + leftRotate(11, d + (a ^ b ^ c) + x[xi] + K[ki+1])
		xi = (xi + 3) & 0xf
		c = d + leftRotate(16, c + (d ^ a ^ b) + x[xi] + K[ki+2])
		xi = (xi + 3) & 0xf
		b = c + leftRotate(23, b + (c ^ d ^ a) + x[xi] + K[ki+3])
		xi = (xi + 3) & 0xf
		ki += 4
	}

	// Round 4
	// I(X,Y,Z) = Y xor (X v not(Z))
	xi = 0;
	for ki < 64 {
		a = b + leftRotate( 6, a + (c ^ (b | ^d)) + x[xi] + K[ki])
		xi = (xi + 7) & 0xf
		d = a + leftRotate(10, d + (b ^ (a | ^c)) + x[xi] + K[ki+1])
		xi = (xi + 7) & 0xf
		c = d + leftRotate(15, c + (a ^ (d | ^b)) + x[xi] + K[ki+2])
		xi = (xi + 7) & 0xf
		b = c + leftRotate(21, b + (d ^ (c | ^a)) + x[xi] + K[ki+3])
		xi = (xi + 7) & 0xf
		ki += 4
	}

	// Update the buffer
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += d
}

func leftRotate(x uint32, rr uint32) uint32 {
	return ((x << rr) | (x >> (32 - rr))) & 0xffffffff
}

func Md5(input string) string {
	var i int
	for i = 0; i < 64; i++ {
		K[i] = uint32(math.Floor(math.Abs(math.Sin(float64(i+1))) * (math.Pow(2, 32))))
	}

	var block [MsgBlockLen]uint8
	var index uint = 0
	msgLen := 0
	for _, msg := range input {
		block[index] = uint8(msg)
		index++
		msgLen += 8
		if index == MsgBlockLen {
			processMsgBlock(block)
			block = [MsgBlockLen]uint8{}
			index = 0
		}
	}

	msgBlockPadLen := MsgBlockLen - 8
	if index >= msgBlockPadLen {
		block = padMsgBlock(block, index, MsgBlockLen)
		processMsgBlock(block)
		block = appendZeros(block, 0, msgBlockPadLen)
	} else {
		block = padMsgBlock(block, index, msgBlockPadLen)
	}

	var j uint = 0
	l := msgLen
	for j < 8 {
		block[msgBlockPadLen+j] = uint8(l & 0xff)
		msgLen >>= 8
		j++
	}

	processMsgBlock(block)

	i = 0
	ri := 0
	res := [16]uint8{}
	out := ""
	for i < 4 {
		w := h[i]
		res[ri]	    = uint8(w & 0xff)
		res[ri+1]	= uint8(w >> 8 & 0xff)
		res[ri+2]	= uint8(w >> 16 & 0xff)
		res[ri+3]	= uint8(w >> 24)
		out += fmt.Sprintf("%x%x%x%x",res[ri],res[ri+1],res[ri+2],res[ri+3])
		i += 1
		ri += 4
	}

	return out
}
