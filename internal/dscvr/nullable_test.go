package dscvr_test

import (
	"encoding/json"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/dscvr"

	"github.com/stretchr/testify/require"
)

func TestNullableIntOrString_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		value    dscvr.NullableIntOrString
		expected string
	}{
		{
			name:     "unset value is null",
			value:    dscvr.NullableIntOrString{},
			expected: `null`,
		},
		{
			name:     "null value",
			value:    dscvr.NullValue(),
			expected: `null`,
		},
		{
			name:     "integer value",
			value:    dscvr.IntValue(42),
			expected: `42`,
		},
		{
			name:     "zero integer value",
			value:    dscvr.IntValue(0),
			expected: `0`,
		},
		{
			name:     "negative integer value",
			value:    dscvr.IntValue(-10),
			expected: `-10`,
		},
		{
			name:     "string value",
			value:    dscvr.StringValue("hello"),
			expected: `"hello"`,
		},
		{
			name:     "empty string value",
			value:    dscvr.StringValue(""),
			expected: `""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.value)
			require.NoError(t, err)
			require.JSONEq(t, tt.expected, string(data))
		})
	}
}

func TestNullableIntOrString_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedInt   int
		expectedStr   string
		expectedNull  bool
		expectedIsInt bool
	}{
		{
			name:         "null input",
			input:        `null`,
			expectedNull: true,
		},
		{
			name:          "integer input",
			input:         `42`,
			expectedIsInt: true,
			expectedInt:   42,
		},
		{
			name:          "zero integer input",
			input:         `0`,
			expectedIsInt: true,
			expectedInt:   0,
		},
		{
			name:          "negative integer input",
			input:         `-10`,
			expectedIsInt: true,
			expectedInt:   -10,
		},
		{
			name:        "string input",
			input:       `"hello"`,
			expectedStr: "hello",
		},
		{
			name:        "empty string input",
			input:       `""`,
			expectedStr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v dscvr.NullableIntOrString
			err := json.Unmarshal([]byte(tt.input), &v)
			require.NoError(t, err)
			require.True(t, v.IsSet())
			require.Equal(t, tt.expectedNull, v.IsNull())
			require.Equal(t, tt.expectedIsInt, v.IsInt())
			require.Equal(t, tt.expectedInt, v.Int())
			require.Equal(t, tt.expectedStr, v.String())
		})
	}
}

func TestNullableIntOrString_RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		value dscvr.NullableIntOrString
	}{
		{
			name:  "null round trip",
			value: dscvr.NullValue(),
		},
		{
			name:  "integer round trip",
			value: dscvr.IntValue(42),
		},
		{
			name:  "string round trip",
			value: dscvr.StringValue("hello"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.value)
			require.NoError(t, err)

			var result dscvr.NullableIntOrString
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			require.Equal(t, tt.value.IsNull(), result.IsNull())
			require.Equal(t, tt.value.IsInt(), result.IsInt())
			require.Equal(t, tt.value.Int(), result.Int())
			require.Equal(t, tt.value.String(), result.String())
		})
	}
}

func TestNullableIntOrString_UnmarshalJSON_InvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid json",
			input: `{invalid}`,
		},
		{
			name:  "boolean input",
			input: `true`,
		},
		{
			name:  "array input",
			input: `[1,2,3]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v dscvr.NullableIntOrString
			err := json.Unmarshal([]byte(tt.input), &v)
			require.Error(t, err)
		})
	}
}
