package reader

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// Reader reads big-endian binary data from a byte slice, tracking position.
type Reader struct {
	data []byte
	pos  int
}

// NewReader creates a Reader over data starting at offset 0.
func NewReader(data []byte) *Reader {
	return &Reader{data: data, pos: 0}
}

// Pos returns the current read position.
func (r *Reader) Pos() int { return r.pos }

// Remaining returns the number of bytes left to read.
func (r *Reader) Remaining() int { return len(r.data) - r.pos }

// Skip advances the reader by n bytes.
func (r *Reader) Skip(n int) error {
	if r.pos+n > len(r.data) {
		return fmt.Errorf("skip %d bytes at offset %d: %w", n, r.pos, io.ErrUnexpectedEOF)
	}

	r.pos += n

	return nil
}

// ReadU1 reads an unsigned 1-byte value.
func (r *Reader) ReadU1() (uint8, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("read u1 at offset %d: %w", r.pos, io.ErrUnexpectedEOF)
	}

	v := r.data[r.pos]
	r.pos++

	return v, nil
}

// ReadU2 reads an unsigned 2-byte big-endian value.
func (r *Reader) ReadU2() (uint16, error) {
	if r.pos+2 > len(r.data) {
		return 0, fmt.Errorf("read u2 at offset %d: %w", r.pos, io.ErrUnexpectedEOF)
	}

	v := binary.BigEndian.Uint16(r.data[r.pos:])
	r.pos += 2

	return v, nil
}

// ReadU4 reads an unsigned 4-byte big-endian value.
func (r *Reader) ReadU4() (uint32, error) {
	if r.pos+4 > len(r.data) {
		return 0, fmt.Errorf("read u4 at offset %d: %w", r.pos, io.ErrUnexpectedEOF)
	}

	v := binary.BigEndian.Uint32(r.data[r.pos:])
	r.pos += 4

	return v, nil
}

// ReadU8 reads an unsigned 8-byte big-endian value.
func (r *Reader) ReadU8() (uint64, error) {
	if r.pos+8 > len(r.data) {
		return 0, fmt.Errorf("read u8 at offset %d: %w", r.pos, io.ErrUnexpectedEOF)
	}

	v := binary.BigEndian.Uint64(r.data[r.pos:])
	r.pos += 8

	return v, nil
}

// ReadS1 reads a signed 1-byte value.
func (r *Reader) ReadS1() (int8, error) {
	v, err := r.ReadU1()
	return int8(v), err
}

// ReadS2 reads a signed 2-byte big-endian value.
func (r *Reader) ReadS2() (int16, error) {
	v, err := r.ReadU2()
	return int16(v), err
}

// ReadS4 reads a signed 4-byte big-endian value.
func (r *Reader) ReadS4() (int32, error) {
	v, err := r.ReadU4()
	return int32(v), err
}

// ReadFloat32 reads a 4-byte IEEE 754 float.
func (r *Reader) ReadFloat32() (float32, error) {
	v, err := r.ReadU4()
	if err != nil {
		return 0, err
	}

	return math.Float32frombits(v), nil
}

// ReadFloat64 reads an 8-byte IEEE 754 double.
func (r *Reader) ReadFloat64() (float64, error) {
	v, err := r.ReadU8()
	if err != nil {
		return 0, err
	}

	return math.Float64frombits(v), nil
}

// ReadBytes reads exactly n bytes.
func (r *Reader) ReadBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("read %d bytes at offset %d: %w", n, r.pos, io.ErrUnexpectedEOF)
	}

	buf := make([]byte, n)
	copy(buf, r.data[r.pos:r.pos+n])
	r.pos += n

	return buf, nil
}

// ReadModifiedUTF8 reads a modified UTF-8 string (Java's format).
// The length prefix (u2) has already been read; this reads the raw bytes
// and decodes modified UTF-8.
func ReadModifiedUTF8(data []byte) string {
	out := make([]rune, 0, len(data))

	i := 0
	for i < len(data) {
		x := data[i]
		if x&0x80 == 0 {
			// Single byte: 0xxxxxxx
			out = append(out, rune(x))
			i++
		} else if x&0xE0 == 0xC0 {
			// Two bytes: 110xxxxx 10xxxxxx
			if i+1 >= len(data) {
				break
			}

			y := data[i+1]
			if y&0xC0 != 0x80 {
				// Malformed - fall back to byte value
				out = append(out, rune(x))
				i++

				continue
			}

			val := rune(x&0x1F)<<6 + rune(y&0x3F)
			out = append(out, val)
			i += 2
		} else if x&0xF0 == 0xE0 {
			// Three bytes: 1110xxxx 10xxxxxx 10xxxxxx
			if i+2 >= len(data) {
				break
			}

			y := data[i+1]

			z := data[i+2]
			if y&0xC0 != 0x80 || z&0xC0 != 0x80 {
				out = append(out, rune(x))
				i++

				continue
			}

			val := rune(x&0x0F)<<12 + rune(y&0x3F)<<6 + rune(z&0x3F)
			out = append(out, val)
			i += 3
		} else {
			// Invalid byte - include as-is
			out = append(out, rune(x))
			i++
		}
	}

	return string(out)
}

// Slice returns a sub-reader starting at the current position with length n.
func (r *Reader) Slice(n int) (*Reader, error) {
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("slice %d bytes at offset %d: %w", n, r.pos, io.ErrUnexpectedEOF)
	}

	sub := &Reader{data: r.data[r.pos : r.pos+n], pos: 0}
	r.pos += n

	return sub, nil
}

// Bytes returns all data in this reader (regardless of position).
func (r *Reader) Bytes() []byte {
	return r.data
}

// RemainingBytes returns the unread portion of data.
func (r *Reader) RemainingBytes() []byte {
	if r.pos >= len(r.data) {
		return nil
	}

	return r.data[r.pos:]
}
