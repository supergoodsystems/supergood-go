package redact

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/supergoodsystems/supergood-go/internal/shared"
)

// sensitive keys are of the form requestHeaders, responseBody etc. These values must
// be mapped to fields in the parsed supergood event
func formatSensitiveKey(keyPath string) ([]string, error) {
	parts := strings.Split(keyPath, ".")
	remainingParts := []string{}

	switch parts[0] {
	case shared.RequestHeadersStr:
		remainingParts = append(remainingParts, "Request", "Headers")
	case shared.RequestBodyStr:
		remainingParts = append(remainingParts, "Request", "Body")
	case shared.ResponseHeadersStr:
		remainingParts = append(remainingParts, "Response", "Headers")
	case shared.ResponseBodyStr:
		remainingParts = append(remainingParts, "Response", "Body")
	default:
		return []string{}, fmt.Errorf("invalid sensitive key value provided: %s", keyPath)
	}

	// Attempting to format indexed array elements (e.g. responseBody.nested.array[].field1)
	// should be parsed as response.body.nested.array.[].field1 to be used by the recursive redaction func
	if len(parts) > 1 {
		for i := 1; i < len(parts); i++ {
			currentPart := parts[i]
			if strings.Contains(currentPart, "[]") {
				arraySplit := strings.Split(currentPart, "[]")
				remainingParts = append(remainingParts, arraySplit[0])
				remainingParts = append(remainingParts, "[]")
			} else {
				remainingParts = append(remainingParts, currentPart)
			}
		}
	}
	return remainingParts, nil
}

// reformatSensitiveKeyPath generates a string that is conformed to a supergood path standard.
// e.g. responsBody.field.nestedarray[1].field2.
// the below function marshals the recursively built string path into a keyPath form expected by supergood
func reformatSensitiveKeyPath(path string) string {
	if strings.HasPrefix(path, "."+shared.RequestHeadersSplitStr) {
		return shared.RequestHeadersStr + strings.TrimPrefix(path, "."+shared.RequestHeadersSplitStr)
	}
	if strings.HasPrefix(path, "."+shared.RequestBodySplitStr) {
		return shared.RequestBodyStr + strings.TrimPrefix(path, "."+shared.RequestBodySplitStr)
	}
	if strings.HasPrefix(path, "."+shared.ResponseHeadersSplitStr) {
		return shared.ResponseHeadersStr + strings.TrimPrefix(path, "."+shared.ResponseHeadersSplitStr)
	}
	if strings.HasPrefix(path, "."+shared.ResponseBodySplitStr) {
		return shared.ResponseBodyStr + strings.TrimPrefix(path, "."+shared.ResponseBodySplitStr)
	}
	return path
}

// parseArrayIndex will take a path element string and returns potential indexes
// retuns -1 if path cannot be parsed into an index
// returns 1 if path represents all indexes
func parseArrayIndex(path string) int {
	if strings.Contains(path, "[]") {
		return 1

	}
	return -1
}

func formatArrayPathPart(path string, index int) string {
	return path + "[" + strconv.Itoa(index) + "]"
}

func formatFieldPathPart(path, current string) string {
	return path + "." + current
}
