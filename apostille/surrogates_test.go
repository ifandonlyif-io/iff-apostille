package apostille

import (
	"bytes"
	"testing"
)

// Inputs use jsonText tokens: <hhhh> is the JSON escape of a UTF-16 code unit
// and <bs> a single backslash.
func TestPairedSurrogateEscapes(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		ok         bool
	}{
		{"no_escapes", `{"a":"b"}`, true},
		{"valid_pair", `{"x":"<d83d><de80>"}`, true},
		{"valid_pair_uppercase", `{"x":"<D83D><DE80>"}`, true},
		{"valid_pair_boundaries", `{"x":"<d800><dc00><dbff><dfff>"}`, true},
		{"valid_pair_in_name", `{"<d83d><de80>":true}`, true},
		{"bmp_escapes_around_surrogate_range", `{"x":"<d7ff><e000><fffd>"}`, true},
		{"literal_replacement_character", `{"x":"<replacement>"}`, true},
		{"escaped_backslash_then_text", `{"x":"<bs><bs>ud800"}`, true},
		{"two_escaped_backslashes_then_text", `{"x":"<bs><bs><bs><bs>ud800"}`, true},
		{"escaped_quote_then_text", `{"x":"<bs>"ud800"}`, true},
		{"outside_a_string_is_left_to_the_json_parser", `<d800>`, true},
		{"lone_high", `{"x":"<d800>"}`, false},
		{"lone_low", `{"x":"<dc00>"}`, false},
		{"lone_high_at_upper_bound", `{"x":"<dbff>"}`, false},
		{"lone_low_at_upper_bound", `{"x":"<dfff>"}`, false},
		{"low_then_high", `{"x":"<dc00><d800>"}`, false},
		{"high_then_high", `{"x":"<d800><d800>"}`, false},
		{"low_then_low", `{"x":"<dc00><dc00>"}`, false},
		{"high_then_bmp_escape", `{"x":"<d800><0041>"}`, false},
		{"high_then_literal", `{"x":"<d800>A"}`, false},
		{"high_then_other_escape", `{"x":"<d800><bs>n"}`, false},
		{"high_then_end_of_string", `{"x":"a<d800>"}`, false},
		{"pair_then_lone_high", `{"x":"<d83d><de80><d800>"}`, false},
		{"escaped_backslash_then_lone_high", `{"x":"<bs><bs><d800>"}`, false},
		{"lone_high_in_name", `{"<d800>":true}`, false},
		{"low_then_high_in_name", `{"<dc00><d800>":true}`, false},
		{"truncated_escape", `{"x":"<bs>ud8`, false},
		{"truncated_low_half", `{"x":"<d800><bs>udc`, false},
		{"non_hex_escape", `{"x":"<bs>ud8zz"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := jsonText(tc.text)
			if err := pairedSurrogateEscapes(raw); (err == nil) != tc.ok {
				t.Fatalf("pairedSurrogateEscapes(%s) = %v, want ok=%v", raw, err, tc.ok)
			}
		})
	}
}

// StrictJSON must never manufacture U+FFFD: a decoded replacement character
// has to be one the input spelled out, literally or as an escape of U+FFFD.
func TestStrictJSONDoesNotManufactureReplacementCharacters(t *testing.T) {
	for _, text := range []string{`{"x":"<dc00><d800>"}`, `{"x":"<d800><d800>"}`, `{"x":"<d800><0041>"}`, `{"<d800><d800>":"k"}`, `["<dc00><dc00>"]`} {
		var dst any
		if err := StrictJSON(jsonText(text), &dst); err == nil {
			t.Errorf("accepted %s as %q", text, dst)
		}
	}
	for _, tc := range []struct{ text, want string }{
		{`{"x":"<replacement>"}`, `<replacement>`},
		{`{"x":"<fffd>"}`, `<replacement>`},
		{`{"x":"<bs><bs>ud800"}`, `<bs>ud800`},
		{`{"x":"<d83d><de80>"}`, `<rocket>`},
	} {
		var dst map[string]string
		if err := StrictJSON(jsonText(tc.text), &dst); err != nil || dst["x"] != string(jsonText(tc.want)) {
			t.Errorf("StrictJSON(%s) = %q, %v; want %q", tc.text, dst["x"], err, jsonText(tc.want))
		}
	}
	// A signed payload spelled with such an escape was never canonical, so
	// envelope verification rejected it before this rule and still does.
	b, s := producerOnly(t)
	p, err := Canonical(producerOnlyStatement(s))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Replace(p, []byte("application/octet-stream"), jsonText("application/octet-stream<d800><d800>"), 1)
	if bytes.Equal(payload, p) {
		t.Fatal("payload was not altered")
	}
	bad := b
	bad.Statement = signRaw(t, s, KindStatement, payload)
	if _, err := VerifyBundle(bad, VerifyOptions{}); err == nil {
		t.Fatal("accepted a signed payload with unpaired surrogate escapes")
	}
}
