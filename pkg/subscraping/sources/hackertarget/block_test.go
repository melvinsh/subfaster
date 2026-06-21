package hackertarget

import "testing"

func TestIsQuotaError(t *testing.T) {
	cases := map[string]bool{
		// real over-quota / rejection bodies (HTTP 200, plaintext)
		"API count exceeded - Increase Quota with Membership": true,
		"error check your search parameter":                   true,
		// healthy "host,ip" data lines must not trip the detector
		"api.projectdiscovery.io,34.73.179.30": false,
		"1.google.com,142.250.217.142":         false,
		"":                                     false,
	}
	for line, want := range cases {
		if got := isQuotaError(line); got != want {
			t.Errorf("isQuotaError(%q) = %v, want %v", line, got, want)
		}
	}
}
