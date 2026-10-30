package httpapi

import (
	"encoding/json"
	"slices"
)

// propertiesBody is a JSON object whose properties are kept as they came, for the routes whose contract has
// additionalProperties false: a property of another type, a null and an unknown one can be told from one that was not sent.
type propertiesBody struct {
	properties map[string]any
}

func (b *propertiesBody) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &b.properties)
}

// texts reads the properties named in allowed as texts, which are returned by name. Its problems name each property
// that is unknown, null or not a string, in alphabetical order; the content of a text is judged by the domain.
func (b propertiesBody) texts(allowed ...string) (map[string]string, []fieldError) {
	names := make([]string, 0, len(b.properties))
	for name := range b.properties {
		names = append(names, name)
	}
	slices.Sort(names)
	texts := map[string]string{}
	var problems []fieldError
	for _, name := range names {
		value := b.properties[name]
		text, isText := value.(string)
		switch {
		case !slices.Contains(allowed, name):
			problems = append(problems, fieldError{Field: name, Message: "is not an accepted field"})
		case value == nil:
			problems = append(problems, fieldError{Field: name, Message: "must not be null"})
		case !isText:
			problems = append(problems, fieldError{Field: name, Message: "must be a string"})
		default:
			texts[name] = text
		}
	}
	return texts, problems
}

// sent returns the text of a property that was sent, or nil when it was not.
func sent(texts map[string]string, name string) *string {
	if text, ok := texts[name]; ok {
		return &text
	}
	return nil
}
