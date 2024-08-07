package remoteconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	domainutils "github.com/supergoodsystems/supergood-go/internal/domain-utils"
	"github.com/supergoodsystems/supergood-go/internal/shared"
)

func (rc *RemoteConfig) MatchRequestAgainstEndpoints(req *http.Request) (*EndpointCacheVal, []error) {
	var errs []error
	domain := domainutils.GetDomainFromHost(req.Host)
	if domain == "" {
		return nil, errs
	}
	endpoints := rc.Get(domain)
	if len(endpoints) == 0 {
		return nil, errs
	}
	for _, endpoint := range endpoints {
		if !strings.EqualFold(req.Method, endpoint.Method) || (req.Method == "" && endpoint.Method != "GET") {
			continue
		}
		testVal, err := stringifyRequestAtLocation(req, endpoint.Location)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		testByteArray := []byte(fmt.Sprintf("%v", testVal))
		match := endpoint.Regex.Match(testByteArray)
		if match {
			return &endpoint, errs
		}
	}
	return nil, errs
}

// stringifyRequestAtLocation takes an endpoint location, which is used to uniquely classify
// a request and stringifies the request object at that location
func stringifyRequestAtLocation(req *http.Request, location string) (string, error) {
	if location == shared.URLStr {
		return req.URL.String(), nil
	}
	if location == shared.DomainStr {
		return domainutils.Domain(req.URL.String()), nil
	}
	if location == shared.SubDomainStr {
		return domainutils.Subdomain(req.URL.String()), nil
	}
	if location == shared.PathStr {
		return req.URL.Path, nil
	}
	if strings.Contains(location, shared.RequestHeadersStr) {
		return getHeaderValueAtLocation(req.Header, location)
	}
	if strings.Contains(location, shared.RequestBodyStr) {
		return getRequestBodyValueAtLocation(req, location)
	}

	return "", fmt.Errorf("unexpected location parameter for RegExp matching: %s", location)
}

// getRequestBodyValueAtLocation retrieves the nested field value of a struct based on the given "location"
func getRequestBodyValueAtLocation(req *http.Request, location string) (string, error) {
	path := strings.Split(location, ".")

	// read in stream and write back to request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	// no nested field provided in location parameter (e.g. "request_body" instead of "request_body.field")
	if len(path) == 1 || !json.Valid(body) {
		return string(body), nil
	}

	var nestedBody map[string]interface{}
	err = json.Unmarshal(body, &nestedBody)
	if err != nil {
		return "", err
	}

	path = path[1:]
	for _, key := range path {
		value, ok := nestedBody[key]
		if !ok {
			return "", fmt.Errorf("field not found: %s", location)
		}

		if nested, ok := value.(map[string]interface{}); ok {
			nestedBody = nested
		} else {
			// If not a map, this is the final value
			return fmt.Sprintf("%v", value), nil
		}
	}
	return "", fmt.Errorf("field not found: %s", location)
}

// getHeaderValueAtLocation retrieves the header value string given a header key "location"
func getHeaderValueAtLocation(headers http.Header, location string) (string, error) {
	path := strings.Split(location, ".")
	// location here is of form: requestHeaders
	if len(path) == 1 {
		headerBytes, err := json.Marshal(headers)
		if err != nil {
			return "", err
		}
		return string(headerBytes), nil
	}

	// location here is of form: requestHeaders.Client-Secret
	if len(path) != 2 {
		return "", fmt.Errorf("invalid header parameter for RegExp matching: %s", location)
	}
	return headers.Get(path[1]), nil

}
