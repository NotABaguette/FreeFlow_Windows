package protocol

import "fmt"

// AAAA response format per record (16 bytes):
// [0:4]  IPv6 prefix (CDN prefix)
// [4]    Flags: bit 7 = isLast, bit 6 = continuation, bit 5 = compressed
// [5]    Sequence number (mod 256)
// [6]    Record index (0-based)
// [7]    Total records in response
// [8:16] Payload data (8 bytes)

const (
	PayloadPerRecord = 8
	MaxRecords       = 8
	MaxPayload       = PayloadPerRecord * MaxRecords // 64 bytes
	FlagIsLast       = 0x80
)

// DecodeAAAARecords extracts payload from AAAA response records.
// Each record is 16 bytes (an IPv6 address). Max 8 records.
// Returns concatenated payload bytes.
func DecodeAAAARecords(records [][]byte) ([]byte, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no AAAA records")
	}
	if len(records) > MaxRecords {
		records = records[:MaxRecords]
	}

	// Sort by record index (byte 6)
	sorted := make([][]byte, len(records))
	copy(sorted, records)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if len(sorted[i]) >= 7 && len(sorted[j]) >= 7 {
				if sorted[i][6] > sorted[j][6] {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}
	}

	var payload []byte
	for _, rec := range sorted {
		if len(rec) < 16 {
			continue
		}
		payload = append(payload, rec[8:16]...)
	}

	return payload, nil
}

// IsErrorResponse checks if the payload starts with 0xFF (error).
func IsErrorResponse(payload []byte) (bool, byte) {
	if len(payload) >= 2 && payload[0] == CmdERR {
		return true, payload[1]
	}
	return false, 0
}

// CheckErrorResponse returns an error if the payload is an Oracle error response.
func CheckErrorResponse(payload []byte) error {
	if isErr, code := IsErrorResponse(payload); isErr {
		return fmt.Errorf("oracle error: %s (0x%02x)", ErrorName(code), code)
	}
	return nil
}
