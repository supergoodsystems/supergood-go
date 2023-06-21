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
	"regexp"
	"strconv"
	"strings"
	"time"
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

	if r.Body == nil {
		r.Body = http.NoBody
	}

	if options.RecordRequestBody {
		body, r.Body = duplicateBody(r.Body)
		body = redactValues(body, options.IncludeSpecifiedRequestBodyKeys)
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
		body = redactValues(body, options.IncludeSpecifiedResponseBodyKeys)
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
	lowerCase := regexp.MustCompile("[a-z]")
	upperCase := regexp.MustCompile("[A-Z]")
	numeric := regexp.MustCompile("[0-9]")
	special := regexp.MustCompile("[^a-zA-Z0-9\\s]")

	var redactInt = func(i int) int {
		s := strconv.Itoa(i)
		s = numeric.ReplaceAllString(s, "1")
		i, _ = strconv.Atoi(s)
		return i
	}

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
	case []uint8:
		return "binary"
	case string:
		b = upperCase.ReplaceAllString(b, "A")
		b = lowerCase.ReplaceAllString(b, "a")
		b = numeric.ReplaceAllString(b, "1")
		b = special.ReplaceAllString(b, "*")
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
			s = numeric.ReplaceAllString(s, "1")
			b, err := strconv.ParseFloat(s, 64)
			if err != nil {
				b = 0
			}
			return b
		}
	case float32:
		if float64(b) == math.Trunc(float64(b)) {
			return float32(redactInt(int(b)))
		} else {
			s := fmt.Sprintf("%f", b)
			s = numeric.ReplaceAllString(s, "1")
			f, err := strconv.ParseFloat(s, 32)
			if err != nil {
				b = 0
			}
			b = float32(f)
			return b
		}
	case nil:
		return nil
	default:
		return "?"
	}
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
