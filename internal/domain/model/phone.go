package model

// Phone is a contact phone: digits with an optional leading "+", 7 to 15 digits (value object).
type Phone struct {
	value string
}

const (
	minPhoneDigits = 7
	maxPhoneDigits = 15
)

// NewPhone accepts raw as is; it does not strip separators or spaces.
func NewPhone(raw string) (Phone, error) {
	digits := raw
	if len(digits) > 0 && digits[0] == '+' {
		digits = digits[1:]
	}
	if len(digits) < minPhoneDigits || len(digits) > maxPhoneDigits {
		return Phone{}, ErrInvalidPhone
	}
	for _, char := range digits {
		if char < '0' || char > '9' {
			return Phone{}, ErrInvalidPhone
		}
	}
	return Phone{value: raw}, nil
}

func (p Phone) String() string {
	return p.value
}
