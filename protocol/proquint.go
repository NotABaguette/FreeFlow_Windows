// Package proquint encodes/decodes binary data as pronounceable words.
//
// Each 16-bit value maps to a 5-character CVCVC pattern:
//   4 bits -> consonant (16 options)
//   2 bits -> vowel (4 options)
//   4 bits -> consonant
//   2 bits -> vowel
//   4 bits -> consonant
//
// Example: 0x7F00 -> "lusab"
//
// Multiple words are joined with "-": "lusab-babad-gutih"
// This encoding carries 2 bytes per 5-char word.
// A 63-char DNS label holds 10 words (59 chars + 4 separators) = 20 bytes.
package protocol

import (
	"fmt"
	"strings"
)

var consonants = [16]byte{'b', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'z'}
var vowels = [4]byte{'a', 'i', 'o', 'u'}

var consonantIdx [256]int
var vowelIdx [256]int

// MaxBytesPerLabel is the max bytes a single proquint DNS label can carry.
// 63 chars max. Each word = 5 chars + 1 separator. 10 words = 59 chars.
// 10 words * 2 bytes = 20 bytes per label.
const MaxBytesPerLabel = 20

func init() {
	for i := range consonantIdx {
		consonantIdx[i] = -1
	}
	for i := range vowelIdx {
		vowelIdx[i] = -1
	}
	for i, c := range consonants {
		consonantIdx[c] = i
	}
	for i, v := range vowels {
		vowelIdx[v] = i
	}
}

// ProquintEncode converts binary data to a proquint string (words joined by "-").
// Each 2 bytes -> 1 word. If len(data) is odd, the last byte is padded with 0.
func ProquintEncode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	// Pad to even length
	if len(data)%2 != 0 {
		padded := make([]byte, len(data)+1)
		copy(padded, data)
		data = padded
	}

	words := make([]string, 0, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		val := uint16(data[i])<<8 | uint16(data[i+1])
		words = append(words, proquintEncodeWord(val))
	}

	return strings.Join(words, "-")
}

// ProquintDecode converts a proquint string back to binary data.
func ProquintDecode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	words := strings.Split(s, "-")
	data := make([]byte, 0, len(words)*2)

	for _, w := range words {
		val, err := proquintDecodeWord(w)
		if err != nil {
			return nil, err
		}
		data = append(data, byte(val>>8), byte(val&0xFF))
	}

	return data, nil
}

func proquintEncodeWord(val uint16) string {
	var buf [5]byte
	buf[0] = consonants[(val>>12)&0x0F]
	buf[1] = vowels[(val>>10)&0x03]
	buf[2] = consonants[(val>>6)&0x0F]
	buf[3] = vowels[(val>>4)&0x03]
	buf[4] = consonants[val&0x0F]
	return string(buf[:])
}

func proquintDecodeWord(w string) (uint16, error) {
	if len(w) != 5 {
		return 0, fmt.Errorf("proquint word must be 5 chars, got %d: %q", len(w), w)
	}

	c0 := consonantIdx[w[0]]
	v0 := vowelIdx[w[1]]
	c1 := consonantIdx[w[2]]
	v1 := vowelIdx[w[3]]
	c2 := consonantIdx[w[4]]

	if c0 < 0 || v0 < 0 || c1 < 0 || v1 < 0 || c2 < 0 {
		return 0, fmt.Errorf("invalid proquint word: %q", w)
	}

	val := uint16(c0)<<12 | uint16(v0)<<10 | uint16(c1)<<6 | uint16(v1)<<4 | uint16(c2)
	return val, nil
}

// IsProquint returns true if the label looks like proquint-encoded data.
func IsProquint(label string) bool {
	words := strings.Split(label, "-")
	if len(words) < 2 {
		return false
	}
	for _, w := range words {
		if len(w) != 5 {
			return false
		}
		if consonantIdx[w[0]] < 0 || vowelIdx[w[1]] < 0 ||
			consonantIdx[w[2]] < 0 || vowelIdx[w[3]] < 0 ||
			consonantIdx[w[4]] < 0 {
			return false
		}
	}
	return true
}
