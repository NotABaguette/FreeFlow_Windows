package protocol

import "fmt"

// FrameHeaderSize is the size of the full frame header in bytes.
const FrameHeaderSize = 8

// Frame wire format:
// [1: command] [1: seqno] [1: frag_idx] [1: frag_total] [4: session_token] [N: data]

// BuildFrame creates a wire-format frame.
func BuildFrame(cmd byte, seqNo, fragIdx, fragTotal uint8, token [4]byte, data []byte) []byte {
	frame := make([]byte, FrameHeaderSize+len(data))
	frame[0] = cmd
	frame[1] = seqNo
	frame[2] = fragIdx
	frame[3] = fragTotal
	copy(frame[4:8], token[:])
	copy(frame[8:], data)
	return frame
}

// ParseFrame extracts fields from a wire-format frame.
func ParseFrame(frame []byte) (cmd byte, seqNo, fragIdx, fragTotal uint8, token [4]byte, data []byte, err error) {
	if len(frame) < FrameHeaderSize {
		err = fmt.Errorf("frame too short: %d bytes, need at least %d", len(frame), FrameHeaderSize)
		return
	}
	cmd = frame[0]
	seqNo = frame[1]
	fragIdx = frame[2]
	fragTotal = frame[3]
	copy(token[:], frame[4:8])
	if len(frame) > FrameHeaderSize {
		data = make([]byte, len(frame)-FrameHeaderSize)
		copy(data, frame[FrameHeaderSize:])
	}
	return
}

// BuildPingFrame creates a PING command frame.
func BuildPingFrame() []byte {
	return BuildFrame(CmdPING, 0, 0, 1, [4]byte{}, nil)
}

// BuildHelloChunkFrame creates a HELLO chunk frame.
// Data: [chunkIdx][totalChunks=4][nonce_hi][nonce_lo][8 bytes pubkey chunk]
func BuildHelloChunkFrame(chunkIdx int, helloNonce uint16, chunkData []byte) []byte {
	data := make([]byte, 0, 4+len(chunkData))
	data = append(data, byte(chunkIdx), 4)
	data = append(data, byte(helloNonce>>8), byte(helloNonce&0xFF))
	data = append(data, chunkData...)
	return BuildFrame(CmdHELLO, uint8(chunkIdx), uint8(chunkIdx), 4, [4]byte{}, data)
}

// BuildRegisterFrame creates a REGISTER frame (single 40-byte frame).
func BuildRegisterFrame(seqNo uint8, token [4]byte, pubkey [32]byte) []byte {
	return BuildFrame(CmdREGISTER, seqNo, 0, 1, token, pubkey[:])
}

// BuildGetBulletinFrame creates a GET_BULLETIN frame.
func BuildGetBulletinFrame(lastSeenID uint16) []byte {
	data := []byte{byte(lastSeenID >> 8), byte(lastSeenID & 0xFF)}
	return BuildFrame(CmdGET_BULLETIN, 0, 0, 1, [4]byte{}, data)
}

// BuildDiscoverFrame creates a DISCOVER frame.
func BuildDiscoverFrame() []byte {
	return BuildFrame(CmdDISCOVER, 0, 0, 1, [4]byte{}, nil)
}

// BuildSendMsgFragment creates a SEND_MSG fragment frame.
// data = [recipientFP(8)][ciphertext_chunk]
func BuildSendMsgFragment(seqNo uint8, fragIdx, fragTotal uint8, token [4]byte, recipientFP []byte, ctChunk []byte) []byte {
	data := make([]byte, 0, len(recipientFP)+len(ctChunk))
	data = append(data, recipientFP...)
	data = append(data, ctChunk...)
	// Ensure even total frame length for proquint
	if (FrameHeaderSize+len(data))%2 != 0 {
		data = append(data, 0x00)
	}
	return BuildFrame(CmdSEND_MSG, seqNo, fragIdx, fragTotal, token, data)
}

// BuildGetMsgFrame creates a GET_MSG frame with a sub-command.
func BuildGetMsgFrame(seqNo uint8, token [4]byte, subCmd byte, extra ...byte) []byte {
	data := make([]byte, 0, 1+len(extra))
	data = append(data, subCmd)
	data = append(data, extra...)
	// Ensure even total frame length for proquint (header=8 + data)
	if (FrameHeaderSize+len(data))%2 != 0 {
		data = append(data, 0x00)
	}
	return BuildFrame(CmdGET_MSG, seqNo, 0, 1, token, data)
}
