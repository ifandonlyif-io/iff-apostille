package apostille

import "testing"

func TestIssuerSchemesRejectSharedAmbiguousCharacters(t *testing.T) {
	for _, value := range []string{"urn:example:x%2Fy", `urn:example:x\y`, "https://example.com/x%2Fy", `https://example.com/x\y`} {
		t.Run(value, func(t *testing.T) {
			if ValidIssuer(value) {
				t.Fatalf("accepted ambiguous issuer %q", value)
			}
		})
	}
}
