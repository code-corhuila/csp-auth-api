package model

import "errors"

// ErrEmptyProfileChange is an edit of the profile that carries no field.
var ErrEmptyProfileChange = errors.New("at least one of name, phone and address is required")

// ProfileChange is the edit a user makes to the personal data of the own account (HU-AUTH-007, ADR-051): the
// fields that were sent, each already valid with the rules of registration. A field that was not sent keeps its value
// and none can be cleared, because the registration requires phone and address (value object).
type ProfileChange struct {
	name    *Name
	phone   *Phone
	address *Address
}

// NewProfileChange validates every field that is not nil. All the invalid ones are reported together, joined, so the
// caller can name each. An edit without any field is ErrEmptyProfileChange.
func NewProfileChange(name, phone, address *string) (ProfileChange, error) {
	if name == nil && phone == nil && address == nil {
		return ProfileChange{}, ErrEmptyProfileChange
	}
	var change ProfileChange
	var problems []error
	if name != nil {
		valid, err := NewName(*name)
		change.name, problems = &valid, appendIfFailed(problems, err)
	}
	if phone != nil {
		valid, err := NewPhone(*phone)
		change.phone, problems = &valid, appendIfFailed(problems, err)
	}
	if address != nil {
		valid, err := NewAddress(*address)
		change.address, problems = &valid, appendIfFailed(problems, err)
	}
	if len(problems) > 0 {
		return ProfileChange{}, errors.Join(problems...)
	}
	return change, nil
}

func appendIfFailed(problems []error, err error) []error {
	if err != nil {
		return append(problems, err)
	}
	return problems
}

// Name is the new name, when the edit carries one.
func (c ProfileChange) Name() (Name, bool) {
	if c.name == nil {
		return Name{}, false
	}
	return *c.name, true
}

// Phone is the new phone, when the edit carries one.
func (c ProfileChange) Phone() (Phone, bool) {
	if c.phone == nil {
		return Phone{}, false
	}
	return *c.phone, true
}

// Address is the new address, when the edit carries one.
func (c ProfileChange) Address() (Address, bool) {
	if c.address == nil {
		return Address{}, false
	}
	return *c.address, true
}
