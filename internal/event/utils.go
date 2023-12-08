package event

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	domainutils "github.com/supergoodsystems/supergood-go/internal/domain-utils"
)

func StringifyAtLocation(event *Event, location string) (string, error) {
	if location == "url" {
		return event.Request.URL, nil
	}
	if location == "domain" {
		return domainutils.Domain(event.Request.URL), nil
	}
	if location == "subdomain" {
		return domainutils.Subdomain(event.Request.URL), nil
	}
	if location == "path" {
		return event.Request.Path, nil
	}
	if strings.Contains(location, "request_headers") {
		return stringifyEventObject(event.Request.Headers)

	}
	if strings.Contains(location, "request_body") {
		return stringifyEventObject(event.Request.Body)
	}

	return "", fmt.Errorf("unexpected location parameter for RegExp matching: %s", location)
}

func stringifyEventObject(obj interface{}) (string, error) {
	headerBytes, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(headerBytes), nil
}

func headersToMap(h http.Header) map[string]string {
	ret := map[string]string{}
	for k, vs := range h {
		ret[k] = strings.Join(vs, ", ")
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
