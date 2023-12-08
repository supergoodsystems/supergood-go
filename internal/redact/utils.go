package redact

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"strconv"
	"strings"

	remoteconfig "github.com/supergoodsystems/supergood-go/internal/remote-config"
)

// sensitive keys are of the form requestHeaders, responseBody etc. These values must
// be mapped to fields in the parsed supergood event
func formatSensitiveKey(keyPath string) ([]string, error) {
	parts := strings.Split(keyPath, ".")
	remainingParts := []string{}

	switch parts[0] {
	case remoteconfig.RequestHeadersStr:
		remainingParts = append(remainingParts, "Request", "Headers")
	case remoteconfig.RequestBodyStr:
		remainingParts = append(remainingParts, "Request", "Body")
	case remoteconfig.ResponseHeadersStr:
		remainingParts = append(remainingParts, "Response", "Headers")
	case remoteconfig.ResponseBodyStr:
		remainingParts = append(remainingParts, "Response", "Headers")
	default:
		return []string{}, fmt.Errorf("invalid sensitive key value provided: %s", keyPath)
	}
	if len(parts) > 1 {
		remainingParts = append(remainingParts, parts[1:]...)
	}

	return remainingParts, nil
}

func parseArrayIndex(subpath string) int {
	// -2 return type here will be used to represent all indecies
	if subpath == "[]" {
		return -2
	}
	// -1 will represent an error
	i, err := strconv.Atoi(subpath)
	if err != nil {
		return -1
	}
	return i
}

func getSize(obj any) int {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(obj)
	if err != nil {
		return -1
	}
	return buf.Len()
}
