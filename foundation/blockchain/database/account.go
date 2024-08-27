package database

type AccountID string

// IsAccountID verifies whether the underlying data represents a valid
// hex-encoded account.
func (a AccountID) IsAccountID() bool {
	const addressLength = 20

	if has0xPrefix(a) {
		a = a[2:]
	}

	return len(a) == 2*addressLength && isHex(a)
}

// has0xPrefix validates the account starts with a 0x.
func has0xPrefix(a AccountID) bool {
	return len(a) >= 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X')
}

// isHex validates the account is a valid hex string.
func isHex(a AccountID) bool {
	if len(a)%2 != 0 {
		return false
	}

	for _, c := range []byte(a) {
		if !isHexCharacter(c) {
			return false
		}
	}

	return true
}

// isHexCharacter validates the character is a valid hex character.
func isHexCharacter(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}
