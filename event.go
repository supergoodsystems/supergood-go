package supergood

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
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
	if options.RecordRequestBody {
		body, r.Body = duplicateBody(r.Body)
	}
	req := &request{
		ID:          id,
		Headers:     formatHeaders(r.Header, options.RedactHeaders),
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
	if options.RecordResponseBody {
		body, res.Body = duplicateBody(res.Body)
	}
	return &response{
		Headers:     formatHeaders(res.Header, options.RedactHeaders),
		Status:      res.StatusCode,
		StatusText:  res.Status,
		RespondedAt: now,
		Body:        body,
	}
}

func formatHeaders(h http.Header, redact map[string]bool) map[string]string {
	ret := map[string]string{}
	for k, vs := range h {
		v := strings.Join(vs, ", ")
		if redact[strings.ToLower(k)] {
			sha := sha1.Sum([]byte(v))
			ret[k] = "redacted:" + hex.EncodeToString(sha[:])
		} else {
			ret[k] = v
		}
	}
	return ret
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
