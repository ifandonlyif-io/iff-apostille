package apostille

import "errors"

// pairedSurrogateEscapes rejects a \uXXXX surrogate escape that is not half of
// a high+low pair, in member names and values alike. It reads the raw text
// because encoding/json, and the JCS parser whenever another \u escape
// follows, decode an unpaired surrogate to U+FFFD instead of failing. A
// literal U+FFFD, an escape of U+FFFD and "ud800" after an escaped backslash
// are ordinary text and pass.
func pairedSurrogateEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			inString = c == '"'
			continue
		}
		if c == '"' {
			inString = false
			continue
		}
		if c != '\\' {
			continue
		}
		// Step onto the escaped character, so that \\ and \" are consumed
		// whole and cannot be mistaken for the start of another escape.
		i++
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		unit, ok := hexCodeUnit(raw, i+1)
		if !ok {
			return errors.New("invalid JSON")
		}
		i += 4
		if unit >= 0xdc00 && unit <= 0xdfff {
			return errors.New("unpaired Unicode surrogate escape")
		}
		if unit < 0xd800 || unit > 0xdbff {
			continue
		}
		if i+2 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return errors.New("unpaired Unicode surrogate escape")
		}
		low, ok := hexCodeUnit(raw, i+3)
		if !ok || low < 0xdc00 || low > 0xdfff {
			return errors.New("unpaired Unicode surrogate escape")
		}
		i += 6
	}
	return nil
}

// hexCodeUnit reads the four hex digits of a \u escape starting at raw[at].
func hexCodeUnit(raw []byte, at int) (uint16, bool) {
	if at < 0 || at+4 > len(raw) {
		return 0, false
	}
	var unit uint16
	for _, c := range raw[at : at+4] {
		switch {
		case c >= '0' && c <= '9':
			unit = unit<<4 | uint16(c-'0')
		case c >= 'a' && c <= 'f':
			unit = unit<<4 | uint16(c-'a'+10)
		case c >= 'A' && c <= 'F':
			unit = unit<<4 | uint16(c-'A'+10)
		default:
			return 0, false
		}
	}
	return unit, true
}
