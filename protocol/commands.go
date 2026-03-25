package protocol

// Command codes for the FreeFlow protocol.
const (
	CmdHELLO        byte = 0x01
	CmdGET_BULLETIN byte = 0x02
	CmdSEND_MSG     byte = 0x03
	CmdGET_MSG      byte = 0x04
	CmdACK          byte = 0x05
	CmdDISCOVER     byte = 0x06
	CmdPING         byte = 0x07
	CmdREGISTER     byte = 0x08
	CmdERR          byte = 0xFF
)

// Error codes returned by the Oracle.
const (
	ErrUnknown       byte = 0x00
	ErrNoSession     byte = 0x01
	ErrInvalidToken  byte = 0x02
	ErrRateLimit     byte = 0x03
	ErrMalformed     byte = 0x04
	ErrNoBulletin    byte = 0x05
	ErrNoMessage     byte = 0x06
	ErrHelloTimeout  byte = 0x07
	ErrHelloConflict byte = 0x08
)

// GET_MSG sub-commands.
const (
	GetMsgCHECK byte = 0x00
	GetMsgFETCH byte = 0x01
	GetMsgACK   byte = 0x02
)

// CommandName returns a human-readable name for a command code.
func CommandName(cmd byte) string {
	switch cmd {
	case CmdHELLO:
		return "HELLO"
	case CmdGET_BULLETIN:
		return "GET_BULLETIN"
	case CmdSEND_MSG:
		return "SEND_MSG"
	case CmdGET_MSG:
		return "GET_MSG"
	case CmdACK:
		return "ACK"
	case CmdDISCOVER:
		return "DISCOVER"
	case CmdPING:
		return "PING"
	case CmdREGISTER:
		return "REGISTER"
	case CmdERR:
		return "ERR"
	default:
		return "UNKNOWN"
	}
}

// ErrorName returns a human-readable name for an error code.
func ErrorName(code byte) string {
	switch code {
	case ErrUnknown:
		return "Unknown"
	case ErrNoSession:
		return "NoSession"
	case ErrInvalidToken:
		return "InvalidToken"
	case ErrRateLimit:
		return "RateLimit"
	case ErrMalformed:
		return "Malformed"
	case ErrNoBulletin:
		return "NoBulletin"
	case ErrNoMessage:
		return "NoMessage"
	case ErrHelloTimeout:
		return "HelloTimeout"
	case ErrHelloConflict:
		return "HelloConflict"
	default:
		return "Unknown"
	}
}
