package dscvr

import "encoding/json"

// NullableIntOrString represents a value that can be one of three states:
// null (explicitly set to null), an integer, or a string.
// The zero value represents an unset field, which is distinct from null.
// Use [NullValue], [IntValue], or [StringValue] to construct values,
// and [NullableIntOrString.IsSet] to check if the value was explicitly assigned.
type NullableIntOrString struct {
	isNull  bool
	isSet   bool
	integer int
	str     string
	isInt   bool
}

func NullValue() NullableIntOrString {
	return NullableIntOrString{isNull: true, isSet: true}
}

func IntValue(v int) NullableIntOrString {
	return NullableIntOrString{isSet: true, integer: v, isInt: true}
}

func StringValue(v string) NullableIntOrString {
	return NullableIntOrString{isSet: true, str: v, isInt: false}
}

func (n NullableIntOrString) MarshalJSON() ([]byte, error) {
	// note: n.isSet is for a parent struct to implement the
	// omitempty support. As MarshalJSON can't return empty []byte
	// simply return null here
	if !n.isSet || n.isNull {
		return []byte("null"), nil
	}
	if n.isInt {
		return json.Marshal(n.integer)
	}
	return json.Marshal(n.str)
}

func (n *NullableIntOrString) UnmarshalJSON(data []byte) error {
	n.isSet = true
	if string(data) == "null" {
		n.isNull = true
		return nil
	}
	var i int
	if err := json.Unmarshal(data, &i); err == nil {
		n.integer = i
		n.isInt = true
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	n.str = s
	return nil
}

func (n NullableIntOrString) IsNull() bool   { return n.isNull }
func (n NullableIntOrString) IsSet() bool    { return n.isSet }
func (n NullableIntOrString) Int() int       { return n.integer }
func (n NullableIntOrString) String() string { return n.str }
func (n NullableIntOrString) IsInt() bool    { return n.isInt }
