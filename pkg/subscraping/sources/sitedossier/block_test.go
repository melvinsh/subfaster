package sitedossier

import "testing"

func TestIsBlockedResponse(t *testing.T) {
	// real captcha page body served on the followed 302 -> /audit
	captcha := `<html><body>Our web servers have detected unusual or excessive requests ` +
		`from your computer or network. Please enter the unique "word" below...`
	cases := []struct {
		path string
		body string
		want bool
	}{
		{"/audit/", "", true},                               // landed on captcha after redirect
		{"/parentdomain/x.com", captcha, true},              // body sentinel (defensive)
		{"/parentdomain/x.com", "<html>real</html>", false}, // normal page
		{"", "", false},
	}
	for _, c := range cases {
		if got := isBlockedResponse(c.path, c.body); got != c.want {
			t.Errorf("isBlockedResponse(%q, ...) = %v, want %v", c.path, got, c.want)
		}
	}
}
