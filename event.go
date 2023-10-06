package supergood

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type event struct {
	Request  *request  `json:"request"`
	Response *response `json:"response,omitempty"`
}

type request struct {
	ID          string            `json:"id"`
	Headers     map[string]string `json:"headers"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Path        string            `json:"path,omitempty"`
	Search      string            `json:"search,omitempty"`
	Body        any               `json:"body,omitempty"`
	RequestedAt time.Time         `json:"requestedAt"`
}

type response struct {
	Headers     map[string]string `json:"headers"`
	Status      int               `json:"status"`
	StatusText  string            `json:"statusText"`
	Body        any               `json:"body,omitempty"`
	RespondedAt time.Time         `json:"respondedAt"`
	Duration    int               `json:"duration"`
}

// overridden in tests
var clock = time.Now

func newRequest(id string, r *http.Request, options *Options) *request {
	var body any

	if options.RecordRequestBody {
		body, r.Body = duplicateBody(r.Body)
		if !options.SkipRedaction {
			body = redactValues(body, options.IncludeSpecifiedRequestBodyKeys)
		}
	}
	req := &request{
		ID:          id,
		Headers:     formatHeaders(r.Header, options.IncludeSpecifiedRequestHeaderKeys),
		Method:      r.Method,
		URL:         r.URL.String(),
		Path:        r.URL.Path,
		Search:      r.URL.RawQuery,
		Body:        body,
		RequestedAt: clock(),
	}

	return req
}

func newResponse(res *http.Response, err error, options *Options) *response {
	now := clock()
	if err != nil {
		return &response{
			Status:      0,
			StatusText:  "HTTP ERROR",
			Body:        err.Error(),
			RespondedAt: now,
		}
	}
	var body any

	// Throwing an error on network failures causes duplicateBody to segfault on nil
	if res.Body == nil {
		res.Body = http.NoBody
	}

	if options.RecordResponseBody {
		body, res.Body = duplicateBody(res.Body)
		if !options.SkipRedaction {
			body = redactValues(body, options.IncludeSpecifiedResponseBodyKeys)
		}
	}
	return &response{
		Headers:     headersToMap(res.Header),
		Status:      res.StatusCode,
		StatusText:  res.Status,
		RespondedAt: now,
		Body:        body,
	}
}

func headersToMap(h http.Header) map[string]string {
	ret := map[string]string{}
	for k, vs := range h {
		ret[k] = strings.Join(vs, ", ")
	}
	return ret
}

func formatHeaders(h http.Header, includedKeys map[string]bool) map[string]string {
	ret := map[string]string{}
	for k, vs := range h {
		v := strings.Join(vs, ", ")
		if !includedKeys[strings.ToLower(k)] {
			sha := sha1.Sum([]byte(v))
			ret[k] = "redacted:" + hex.EncodeToString(sha[:])
		} else {
			ret[k] = v
		}
	}
	return ret
}

func redactValues(b any, includedKeys map[string]bool) any {
	switch b := b.(type) {
	case map[string]any:
		for k, v := range b {
			if includedKeys[k] {
				b[k] = v
			} else {
				b[k] = redactValues(v, includedKeys)
			}
		}
		return b
	case []any:
		for i, v := range b {
			b[i] = redactValues(v, includedKeys)
		}
		return b
	case []byte:
		return "binary"
	case string:
		b = redactStr(b)
		return b
	case bool:
		b = false
		return b
	case int:
		b = redactInt(b)
		return b
	case float64:
		if b == math.Trunc(b) {
			b = float64(redactInt(int(b)))
			return b
		} else {
			s := fmt.Sprintf("%f", b)
			redacted := ""
			for _, rune := range s {
				if rune == '.' {
					redacted += "."
				} else {
					redacted += "1"
				}
			}
			b, err := strconv.ParseFloat(redacted, 64)
			if err != nil {
				b = 0
			}
			return b
		}
	case nil:
		return nil
	default:
		return "?"
	}
}

func redactStr(str string) string {
	redacted := ""
	for _, rune := range str {
		switch {
		case unicode.IsUpper(rune):
			redacted += "A"
		case unicode.IsLower(rune):
			redacted += "a"
		case unicode.IsNumber(rune):
			redacted += "1"
		case unicode.IsSpace(rune):
			redacted += " "
		default:
			redacted += "*"
		}
	}
	return redacted
}

func redactInt(i int) int {
	str := strconv.Itoa(i)
	rstr := redactStr(str)
	istr, _ := strconv.Atoi(rstr)
	return istr
}

type readCloser struct {
	c io.ReadCloser
	r *bytes.Reader
	e error
}

func (rc *readCloser) Read(b []byte) (int, error) {
	if rc.e != nil {
		return 0, rc.e
	}
	return rc.r.Read(b)
}

func (rc *readCloser) Close() error {
	return rc.c.Close()
}

func duplicateBody(r io.ReadCloser) (body any, rc io.ReadCloser) {
	if r == nil {
		return nil, nil
	}

	b, err := io.ReadAll(r)
	rc = &readCloser{c: r, r: bytes.NewReader(b), e: err}

	if !utf8.Valid(b) {
		body = b
	} else {
		body = map[string]any{}
		if err := json.Unmarshal(b, &body); err != nil {
			body = string(b)
		}
	}
	return
}
