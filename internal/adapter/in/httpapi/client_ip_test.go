package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func requestFrom(remoteAddr string, forwardedFor ...string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, loginPath, nil)
	request.RemoteAddr = remoteAddr
	for _, value := range forwardedFor {
		request.Header.Add("X-Forwarded-For", value)
	}
	return request
}

func TestClientAddressIsTheLastEntryTheGatewayAppended(t *testing.T) {
	cases := map[string]struct {
		request *http.Request
		want    string
	}{
		"one entry":                    {requestFrom("10.0.0.5:4000", "203.0.113.7"), "203.0.113.7"},
		"the client forged the first":  {requestFrom("10.0.0.5:4000", "1.2.3.4, 203.0.113.7"), "203.0.113.7"},
		"entries with spaces":          {requestFrom("10.0.0.5:4000", " 1.2.3.4 ,  203.0.113.7 "), "203.0.113.7"},
		"several header lines":         {requestFrom("10.0.0.5:4000", "1.2.3.4", "203.0.113.7"), "203.0.113.7"},
		"ipv6 is written canonically":  {requestFrom("10.0.0.5:4000", "2001:DB8:0:0:0:0:0:1"), "2001:db8::1"},
		"an ipv4-mapped ipv6 is ipv4":  {requestFrom("10.0.0.5:4000", "::ffff:203.0.113.7"), "203.0.113.7"},
		"no header uses the peer":      {requestFrom("198.51.100.9:5555"), "198.51.100.9"},
		"ipv6 peer without a header":   {requestFrom("[2001:db8::2]:5555"), "2001:db8::2"},
		"empty header uses the peer":   {requestFrom("198.51.100.9:5555", ""), "198.51.100.9"},
		"garbage entry uses the peer":  {requestFrom("198.51.100.9:5555", "1.2.3.4, not-an-address"), "198.51.100.9"},
		"peer without a port":          {requestFrom("198.51.100.9"), "198.51.100.9"},
		"nothing usable gives nothing": {requestFrom("unix-socket"), ""},
	}
	for name, c := range cases {
		if got := clientAddress(c.request); got != c.want {
			t.Errorf("%s: clientAddress() = %q, want %q", name, got, c.want)
		}
	}
}
